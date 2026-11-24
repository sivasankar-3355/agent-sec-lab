import { Router } from "express";
import { readPrincipal } from "../auth.js";

export function createMeRouter(): Router {
  const router = Router();

  router.get("/me", (_req, res) => {
    const principal = readPrincipal(res);
    res.status(200).json({ principal: principal?.principal ?? null, scopes: principal?.scopes ?? [] });
  });

  return router;
}
