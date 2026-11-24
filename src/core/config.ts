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
