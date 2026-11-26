import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { AppError, ValidationError } from "../../core/errors.js";
import type { ResolvedTarget } from "../protocols.js";
import type { TargetResolver, ToolTargetKind, ToolTargetRule } from "./types.js";

const MAX_TARGET_CHARS = 2048;
const DENIED_HOSTNAMES: ReadonlySet<string> = new Set([
  "localhost",
  "metadata",
  "metadata.google.internal",
  "instance-data",
]);

/**
 * Hostnames that are never acceptable, regardless of what DNS says. DNS-based
 * checks still run; this only catches names that are ambiguous or commonly
 * abused for metadata access.
 */
function assertHostname(host: string): void {
  if (isIP(host) !== 0) {
    if (isIP(host) === 6 && ipv6Bytes(host) === undefined) {
      throw new ValidationError("invalid IPv6 target");
    }
    return;
  }
  if (host.length === 0 || host.length > 253) throw new ValidationError("invalid target hostname");
  for (const label of host.split(".")) {
    if (label.length === 0 || label.length > 63) throw new ValidationError("invalid target hostname label");
    if (!/^[a-z0-9-]+$/.test(label)) throw new ValidationError("invalid target hostname label");
    if (label.startsWith("-") || label.endsWith("-")) throw new ValidationError("invalid target hostname label");
  }
  if (
    DENIED_HOSTNAMES.has(host) ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    throw new AppError("tool_target_denied", `target hostname '${host}' is not permitted`, 403);
  }
}

function rawTarget(raw: string): string {
  if (typeof raw !== "string") throw new ValidationError("target must be a string");
  const value = raw.trim();
  if (value.length === 0 || value.length > MAX_TARGET_CHARS) {
    throw new ValidationError("target must be between 1 and 2048 characters");
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0020\u007F]/.test(value)) throw new ValidationError("target must not contain whitespace or control characters");
  if (value.includes("\\")) throw new ValidationError("target must not contain backslashes");
  if (value.startsWith("//")) throw new ValidationError("target must not be scheme-relative");
  return value;
}

function stripBrackets(value: string): string {
  return value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
}

function stripTrailingDot(value: string): string {
  return isIP(value) === 0 ? value.replace(/\.+$/, "") : value;
}

export interface ParsedToolTarget {
  input: string;
  canonical: string;
  host: string;
  scheme?: string;
  port?: number;
}

/**
 * Parse and canonicalize a target without side effects. Comparison against
 * the approved scope always uses this canonical form so case, trailing dots
 * and default ports cannot create alternate spellings of the same target.
 */
export function parseToolTarget(raw: string, kind: ToolTargetKind): ParsedToolTarget {
  const value = rawTarget(raw);

  if (kind === "url" || (kind === "host-or-url" && /^[a-z][a-z0-9+.-]*:\/\//i.test(value))) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new ValidationError("invalid target URL");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new ValidationError("target URL scheme must be http or https");
    }
    if (url.username !== "" || url.password !== "") {
      throw new ValidationError("target URL must not contain userinfo");
    }
    url.hash = "";
    const host = stripTrailingDot(stripBrackets(url.hostname).toLowerCase());
    assertHostname(host);
    const scheme = url.protocol.slice(0, -1);
    const port = url.port !== "" ? Number(url.port) : undefined;
    const canonical = `${scheme}://${isIP(host) === 6 ? `[${host}]` : host}${port !== undefined ? `:${port}` : ""}${url.pathname}${url.search}`;
    return {
      input: value,
      canonical,
      host,
      scheme,
      ...(port !== undefined ? { port } : {}),
    };
  }

  if (value.includes("/") || value.includes("?") || value.includes("#") || value.includes("@")) {
    throw new ValidationError("host target must not contain a path, query, fragment or userinfo");
  }

  let url: URL;
  try {
    // A sentinel scheme lets the URL parser canonicalize host[:port], including
    // bracketed IPv6 literals, without accepting a real URL.
    url = new URL(`http://${value}`);
  } catch {
    throw new ValidationError("invalid target host");
  }
  if (url.username !== "" || url.password !== "" || url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    throw new ValidationError("invalid target host");
  }
  const host = stripTrailingDot(stripBrackets(url.hostname).toLowerCase());
  assertHostname(host);
  const port = url.port !== "" ? Number(url.port) : undefined;
  const canonical = `${isIP(host) === 6 ? `[${host}]` : host}${port !== undefined ? `:${port}` : ""}`;
  return {
    input: value,
    canonical,
    host,
    ...(port !== undefined ? { port } : {}),
  };
}

/** Canonicalize a list of trusted scope strings, reporting the invalid ones. */
export function canonicalizeScopeTargets(
  raws: readonly string[],
  kind: ToolTargetKind,
): { values: readonly string[]; invalid: readonly string[] } {
  const values = new Set<string>();
  const invalid: string[] = [];
  for (const raw of raws) {
    try {
      values.add(parseToolTarget(raw, kind).canonical);
    } catch {
      invalid.push(raw);
    }
  }
  return { values: [...values], invalid };
}

/**
 * Enforce the target against both trusted authorities: the run record's
 * approved scope and the signed run grant. The grant may narrow the run but
 * may never exceed it.
 */
export function assertTargetInScope(input: {
  canonical: string;
  kind: ToolTargetKind;
  approvedTargets: readonly string[];
  runTargets: readonly string[];
}): readonly string[] {
  const run = canonicalizeScopeTargets(input.runTargets, input.kind);
  const approved = canonicalizeScopeTargets(input.approvedTargets, input.kind);
  if (run.values.length === 0) {
    throw new AppError("tool_target_denied", "the trusted run has no valid approved targets", 403);
  }
  if (approved.invalid.length > 0) {
    throw new AppError("tool_target_denied", "the signed run grant contains an invalid target", 403);
  }
  const runSet = new Set(run.values);
  for (const target of approved.values) {
    if (!runSet.has(target)) {
      throw new AppError("tool_target_denied", "the signed run grant exceeds the trusted run scope", 403);
    }
  }
  if (!approved.values.includes(input.canonical)) {
    throw new AppError("tool_target_denied", `target '${input.canonical}' is outside the signed run grant`, 403);
  }
  if (!runSet.has(input.canonical)) {
    throw new AppError("tool_target_denied", `target '${input.canonical}' is outside the trusted run scope`, 403);
  }
  return approved.values;
}

/** Resolve hostnames and reject private, loopback, link-local and reserved IPs. */
export async function resolveParsedTarget(
  parsed: ParsedToolTarget,
  rule: ToolTargetRule,
  resolver: TargetResolver,
): Promise<ResolvedTarget> {
  const allowPrivate = rule.allowPrivate === true;
  let addresses: string[];

  if (isIP(parsed.host) !== 0) {
    addresses = [parsed.host];
  } else if (rule.resolve) {
    try {
      addresses = [...new Set(await resolver.resolve(parsed.host))];
    } catch {
      throw new AppError("tool_target_unresolved", `target '${parsed.host}' could not be resolved`, 403);
    }
    if (addresses.length === 0) {
      throw new AppError("tool_target_unresolved", `target '${parsed.host}' has no addresses`, 403);
    }
  } else {
    addresses = [];
  }

  if (!allowPrivate) {
    for (const address of addresses) {
      if (isDisallowedIp(address)) {
        throw new AppError(
          "tool_target_denied",
          `target '${parsed.host}' resolves to a private, loopback, link-local or reserved address`,
          403,
        );
      }
    }
  }

  return {
    input: parsed.input,
    canonical: parsed.canonical,
    host: parsed.host,
    addresses,
    allowPrivate,
    ...(parsed.scheme !== undefined ? { scheme: parsed.scheme } : {}),
    ...(parsed.port !== undefined ? { port: parsed.port } : {}),
  };
}

export class DnsTargetResolver implements TargetResolver {
  async resolve(hostname: string): Promise<readonly string[]> {
    const records = await lookup(hostname, { all: true, verbatim: true });
    return records.map((record) => record.address);
  }
}

/** True for addresses that must not be reached by default. */
export function isDisallowedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isDisallowedIpv4(ip);
  if (version === 6) {
    const bytes = ipv6Bytes(ip);
    return bytes === undefined ? true : isDisallowedIpv6(bytes);
  }
  return true;
}

function ipv4ToInt(ip: string): number | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4) return undefined;
  const nums = parts.map((part) => (/^\d{1,3}$/.test(part) ? Number(part) : Number.NaN));
  if (nums.some((num) => !Number.isInteger(num) || num < 0 || num > 255)) return undefined;
  return (((nums[0]! << 24) | (nums[1]! << 16) | (nums[2]! << 8) | nums[3]!) >>> 0);
}

function inIpv4Cidr(value: number, base: string, prefix: number): boolean {
  const baseValue = ipv4ToInt(base);
  if (baseValue === undefined) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (baseValue & mask);
}

const IPV4_DENY: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

function isDisallowedIpv4(ip: string): boolean {
  const value = ipv4ToInt(ip);
  if (value === undefined) return true;
  return IPV4_DENY.some(([base, prefix]) => inIpv4Cidr(value, base, prefix));
}

function isDisallowedIpv4Bytes(bytes: readonly number[]): boolean {
  if (bytes.length !== 4) return true;
  return isDisallowedIpv4(`${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`);
}

function isDisallowedIpv6(bytes: readonly number[]): boolean {
  if (bytes.length !== 16) return true;
  if (bytes.every((byte) => byte === 0)) return true;
  if (bytes.slice(0, 15).every((byte) => byte === 0) && bytes[15] === 1) return true;

  // ::ffff:0:0/96 (IPv4-mapped) and 64:ff9b::/96 (NAT64) embed IPv4 addresses.
  if (bytes.slice(0, 10).every((byte) => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return isDisallowedIpv4Bytes(bytes.slice(12));
  }
  if (
    bytes[0] === 0x00 &&
    bytes[1] === 0x64 &&
    bytes[2] === 0xff &&
    bytes[3] === 0x9b &&
    bytes.slice(4, 12).every((byte) => byte === 0)
  ) {
    return isDisallowedIpv4Bytes(bytes.slice(12));
  }

  // Deprecated IPv4-compatible ::/96.
  if (bytes.slice(0, 12).every((byte) => byte === 0)) return true;
  // Unique local fc00::/7.
  if ((bytes[0]! & 0xfe) === 0xfc) return true;
  // Link-local fe80::/10.
  if (bytes[0] === 0xfe && (bytes[1]! & 0xc0) === 0x80) return true;
  // Multicast ff00::/8.
  if (bytes[0] === 0xff) return true;
  // Documentation 2001:db8::/32.
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) return true;
  // 6to4 2002::/16.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return true;
  // Teredo 2001::/32.
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x00 && bytes[3] === 0x00) return true;
  // Benchmarking 2001:2::/48.
  if (
    bytes[0] === 0x20 &&
    bytes[1] === 0x01 &&
    bytes[2] === 0x00 &&
    bytes[3] === 0x02 &&
    bytes[4] === 0x00 &&
    bytes[5] === 0x00
  ) {
    return true;
  }
  // ORCHID 2001:10::/28.
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x00 && (bytes[3]! & 0xf0) === 0x10) return true;
  // Discard-only 100::/64.
  if (bytes[0] === 0x01 && bytes[1] === 0x00 && bytes.slice(2, 8).every((byte) => byte === 0)) return true;

  return false;
}

function ipv6Bytes(ip: string): number[] | undefined {
  const value = ip.toLowerCase();
  if (value.includes("%")) return undefined;

  let normalized = value;
  const lastColon = normalized.lastIndexOf(":");
  const tail = normalized.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = ipv4ToInt(tail);
    if (v4 === undefined) return undefined;
    const high = ((v4 >>> 16) & 0xffff).toString(16);
    const low = (v4 & 0xffff).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const halves = normalized.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] === "" ? [] : halves[0]!.split(":");
  const tailGroups = halves.length === 2 && halves[1] !== "" ? halves[1]!.split(":") : [];
  if (halves.length === 1 && head.length !== 8) return undefined;
  if (halves.length === 2 && head.length + tailGroups.length >= 8) return undefined;

  const groups: number[] = [];
  const push = (group: string): boolean => {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return false;
    groups.push(Number.parseInt(group, 16));
    return true;
  };
  for (const group of head) if (!push(group)) return undefined;
  if (halves.length === 2) {
    while (groups.length + tailGroups.length < 8) groups.push(0);
  }
  for (const group of tailGroups) if (!push(group)) return undefined;
  if (groups.length !== 8) return undefined;

  const bytes: number[] = [];
  for (const group of groups) {
    bytes.push((group >>> 8) & 0xff, group & 0xff);
  }
  return bytes;
}
