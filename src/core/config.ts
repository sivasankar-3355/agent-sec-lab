import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).default("info"),
  HTTP_HOST: z.string().trim().min(1).default("127.0.0.1"),
  HTTP_PORT: z.coerce.number().int().positive().max(65535).default(3000),
  MONGODB_URI: z.string().trim().min(1).default("mongodb://127.0.0.1:27017"),
  MONGODB_DB: z.string().trim().min(1).default("agentseclab"),
  QDRANT_URL: z.string().trim().min(1).default("http://127.0.0.1:6333"),
  REDIS_URL: z.string().trim().min(1).default("redis://127.0.0.1:6379"),
  AGENT_HOST: z.string().trim().min(1).default("127.0.0.1"),
  AGENT_PORT: z.coerce.number().int().positive().max(65535).default(3001),
  ORCHESTRATOR_A2A_URL: z.string().trim().default(""),
  RECON_A2A_URL: z.string().trim().default(""),
  KNOWLEDGE_A2A_URL: z.string().trim().default(""),
  REPORT_A2A_URL: z.string().trim().default(""),
  // Base URL of the internal Security Token Service (STS). The API gateway uses
  // it to mint run tokens; the orchestrator uses it for per-hop delegation.
  // Empty = control not wired (fail-closed: no run token can be issued).
  STS_URL: z.string().trim().default(""),
  STS_HOST: z.string().trim().min(1).default("127.0.0.1"),
  STS_PORT: z.coerce.number().int().positive().max(65535).default(3002),
  // ---- User authentication (API gateway only, HS256) ----
  // Dedicated symmetric secret. Never shared with the STS or worker agents.
  USER_JWT_SECRET: z.string().trim().default(""),
  USER_JWT_ISS: z.string().trim().min(1).default("agent-sec-lab-user"),
  USER_JWT_AUD: z.string().trim().min(1).default("api-gateway"),
  USER_TOKEN_TTL: z.coerce.number().int().positive().max(86400).default(1800),
  // ---- Workload tokens (STS only, asymmetric RS256) ----
  STS_ISS: z.string().trim().min(1).default("agent-sec-lab"),
  STS_KEY_ID: z.string().trim().min(1).default("sts-key-v1"),
  // Private signing key: STS only. Absent anywhere else keeps fail-closed.
  STS_PRIVATE_KEY: z.string().trim().default(""),
  // Single public verification PEM (uses STS_KEY_ID) and/or a JSON map of
  // kid -> public PEM for rotation. Shared with every workload verifier.
  STS_PUBLIC_KEY: z.string().trim().default(""),
  STS_PUBLIC_KEYS: z.string().trim().default(""),
  WORKLOAD_TOKEN_TTL: z.coerce.number().int().positive().max(86400).default(300),
  RUN_TOKEN_TTL: z.coerce.number().int().positive().max(86400).default(1800),
  CHILD_TOKEN_TTL: z.coerce.number().int().positive().max(86400).default(600),
});

export type Config = z.output<typeof envSchema>;

export function loadConfig(source: NodeJS.ProcessEnv = process.env): Config {
  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    throw new Error(`invalid environment configuration: ${detail}`);
  }
  return parsed.data;
}
