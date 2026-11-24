import { Router } from "express";
import { z } from "zod";
import bcrypt from "bcryptjs";
import type { Logger } from "pino";
import { AppError, UnauthenticatedError } from "../../core/errors.js";
import { newId } from "../../core/ids.js";
import { USER_SCOPES } from "../../security/audience.js";
import type { UserAuthProvider } from "../../security/protocols.js";
import type { UsersRepository } from "../../db/repositories/contracts.js";
import { parseBody } from "./contract.js";

export interface AuthRouterDeps {
  log: Logger;
  users: UsersRepository;
  userAuth?: UserAuthProvider;
}

const HASH_ROUNDS = 10;

const emailSchema = z.string().trim().email().max(320).transform((value) => value.toLowerCase());

const registerSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(10).max(1024),
  })
  .strict();

const loginSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(1).max(1024),
  })
  .strict();

export function createAuthRouter(deps: AuthRouterDeps): Router {
  const router = Router();

  router.post("/auth/register", async (req, res) => {
    const body = parseBody(registerSchema, req.body);
    if (deps.userAuth === undefined) {
      throw new AppError("internal_error", "user authentication is not configured", 500);
    }
    const existing = await deps.users.getByEmail(body.email);
    if (existing) {
      throw new AppError("conflict", "email is already registered", 409);
    }
    const passwordHash = await bcrypt.hash(body.password, HASH_ROUNDS);
    const user = await deps.users.create({
      userId: `user:${newId()}`,
      email: body.email,
      passwordHash,
      scopes: [...USER_SCOPES],
    });
    deps.log.info({ userId: user.userId }, "user registered");
    res.status(201).json({ user_id: user.userId });
  });

  router.post("/auth/login", async (req, res) => {
    const body = parseBody(loginSchema, req.body);
    if (deps.userAuth === undefined) {
      throw new AppError("internal_error", "user authentication is not configured", 500);
    }
    const user = await deps.users.getByEmail(body.email);
    const valid = user !== null && (await bcrypt.compare(body.password, user.passwordHash));
    if (!valid) {
      throw new UnauthenticatedError("invalid email or password");
    }
    const token = await deps.userAuth.mintUserToken(user.userId, user.scopes);
    res.status(200).json({ token, user_id: user.userId, scopes: [...user.scopes] });
  });

  return router;
}
