import { createLogger } from "../core/logger.js";
import { bootWorker } from "../agents/boot.js";
import { ReconExecutor, reconAcceptedKinds } from "../agents/recon/handler.js";

bootWorker("recon", reconAcceptedKinds, new ReconExecutor()).catch((err) => {
  const fallback = createLogger("error");
  fallback.error({ err }, "failed to start recon worker");
  process.exit(1);
});