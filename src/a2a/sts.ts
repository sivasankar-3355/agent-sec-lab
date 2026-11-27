import { A2AError } from "../core/errors.js";
import { withDeadline } from "../core/resilience/abort.js";
import type { MintRunTokenInput, TokenExchangeRequest } from "../security/protocols.js";
import { STS_EXCHANGE_PATH, STS_ISSUE_PATH, STS_MINT_PATH } from "../security/audience.js";
import type { TokenExchanger } from "../agents/orchestrator/broker.js";

export interface STSClientOptions {
  /** The workload's bearer token, used for token-exchange. */
  workloadToken?: string;
  /** Shared bootstrap secret, used to obtain the workload token from token-issue. */
  bootstrapSecret?: string;
  timeoutMs?: number;
}

/**
 * Client for the STS's internal endpoints.
 * - `issue` presents the bootstrap secret to token-issue to obtain the
 *   caller's own workload token (EKS: replaced by workload identity / IRSA).
 * - `mintRun` presents the gateway workload token to token-mint and receives a
 *   run-bound workload token validated by the STS against the run record.
 * - `exchange` presents the orchestrator workload token plus a run token to
 *   token-exchange and receives a per-hop child token.
 *
 * Every call is bounded end-to-end (headers and body). The STS is a trusted
 * internal service, but a hung token call must not become a hung agent.
 */
export class STSClient implements TokenExchanger {
  private readonly base: string;
  private readonly workloadToken: string | undefined;
  private readonly bootstrapSecret: string | undefined;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, options: STSClientOptions) {
    this.base = baseUrl.replace(/\/+$/, "");
    this.workloadToken = options.workloadToken;
    this.bootstrapSecret = options.bootstrapSecret;
    this.timeoutMs = options.timeoutMs ?? 5000;
  }

  async issue(workload: string, scopes: readonly string[]): Promise<string> {
    if (this.bootstrapSecret === undefined) {
      throw new A2AError("no bootstrap secret available to request a workload token", 503);
    }
    const response = await this.post(
      STS_ISSUE_PATH,
      { "x-bootstrap": this.bootstrapSecret },
      { workload, scopes: [...scopes] },
      "token issue",
    );
    if (!response.ok) {
      throw new A2AError(`token issue returned ${response.status}: ${response.text.slice(0, 200)}`, response.status);
    }
    return this.parseToken(response.text, "token issue");
  }

  /** Gateway-side: request a run-bound workload token from the STS. */
  async mintRun(input: MintRunTokenInput): Promise<string> {
    if (this.workloadToken === undefined) {
      throw new A2AError("no gateway workload token available to mint a run token", 503);
    }
    const response = await this.post(
      STS_MINT_PATH,
      { authorization: `Bearer ${this.workloadToken}` },
      {
        runId: input.runId,
        targets: [...input.targets],
        actions: [...input.actions],
        correlationId: input.correlationId,
      },
      "token mint",
    );
    if (!response.ok) {
      throw new A2AError(`token mint returned ${response.status}: ${response.text.slice(0, 200)}`, response.status);
    }
    return this.parseToken(response.text, "token mint");
  }

  async exchange(runToken: string, request: TokenExchangeRequest): Promise<string> {
    return this.bearerCall(STS_EXCHANGE_PATH, "token exchange", {
      runToken,
      audience: request.audience,
      actions: [...request.actions],
    });
  }

  private async bearerCall(path: string, label: string, body: Record<string, unknown>): Promise<string> {
    if (this.workloadToken === undefined) {
      throw new A2AError(`no workload token available for ${label}`, 503);
    }
    const response = await this.post(
      path,
      { authorization: `Bearer ${this.workloadToken}` },
      body,
      label,
    );
    if (!response.ok) {
      throw new A2AError(`${label} returned ${response.status}: ${response.text.slice(0, 200)}`, response.status);
    }
    return this.parseToken(response.text, label);
  }

  private parseToken(text: string, label: string): string {
    let parsed: { token?: string };
    try {
      parsed = JSON.parse(text) as { token?: string };
    } catch {
      throw new A2AError(`${label} returned malformed JSON`);
    }
    if (typeof parsed.token !== "string" || parsed.token.length === 0) {
      throw new A2AError(`${label} did not return a token`);
    }
    return parsed.token;
  }

  private async post(
    path: string,
    headers: Record<string, string>,
    body: object,
    label: string,
  ): Promise<{ ok: boolean; status: number; text: string }> {
    return withDeadline(
      async (signal) => {
        const response = await fetch(`${this.base}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify(body),
          // Internal STS endpoints never redirect; fail instead of following.
          redirect: "error",
          signal,
        });
        const text = await response.text();
        return { ok: response.ok, status: response.status, text };
      },
      { timeoutMs: this.timeoutMs, label: `sts.${label}` },
    );
  }
}
