import { createLogger } from "../core/logger.js";
import { bootWorker } from "../agents/boot.js";
import { ReportExecutor, reportAcceptedKinds } from "../agents/report/handler.js";

bootWorker("report", reportAcceptedKinds, new ReportExecutor()).catch((err) => {
  const fallback = createLogger("error");
  fallback.error({ err }, "failed to start report worker");
  process.exit(1);
});