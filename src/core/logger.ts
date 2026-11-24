import { pino, type Logger, type LevelWithSilent } from "pino";

const redactPaths = [
  "req.headers.authorization",
  "*.password",
  "*.secret",
  "*.token",
  "*.apiKey",
  "*.api_key",
];

export function createLogger(level: string, enabled = true): Logger {
  return pino({
    level: level as LevelWithSilent,
    enabled,
    redact: { paths: redactPaths, censor: "[REDACTED]" },
    base: null,
  });
}
