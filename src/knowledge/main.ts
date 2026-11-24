import { createLogger } from "../core/logger.js";
import { bootWorker } from "../agents/boot.js";
import { KnowledgeExecutor, knowledgeAcceptedKinds } from "../agents/knowledge/handler.js";

bootWorker("knowledge", knowledgeAcceptedKinds, new KnowledgeExecutor()).catch((err) => {
  const fallback = createLogger("error");
  fallback.error({ err }, "failed to start knowledge worker");
  process.exit(1);
});