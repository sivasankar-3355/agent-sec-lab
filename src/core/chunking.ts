import { stableHash } from "./ids.js";

export interface Chunk {
  index: number;
  text: string;
  contentHash: string;
}

export function chunkText(text: string, maxChars = 1024): Chunk[] {
  const normalized = text.replaceAll("\r\n", "\n").trim();
  if (normalized.length === 0) return [];

  const words = normalized.split(/\s+/);
  const pieces: string[] = [];
  let current = "";

  for (const word of words) {
    const candidate = current === "" ? word : `${current} ${word}`;
    if (candidate.length > maxChars && current !== "") {
      pieces.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }

  if (current !== "") pieces.push(current);

  return pieces.map((text, index) => ({ index, text, contentHash: stableHash(text) }));
}