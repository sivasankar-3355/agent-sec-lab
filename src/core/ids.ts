import { createHash } from "node:crypto";
import { v7 as uuidv7 } from "uuid";

export function newId(): string {
  return uuidv7();
}

export function stableHash(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}
