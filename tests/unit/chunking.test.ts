import { describe, expect, it } from "vitest";
import { chunkText } from "../../src/core/chunking.js";
import { stableHash } from "../../src/core/ids.js";

describe("chunkText", () => {
  it("returns no chunks for empty input", () => {
    expect(chunkText("  ")).toEqual([]);
  });

  it("keeps short content in a single chunk with a stable hash", () => {
    const chunks = chunkText("hello world");
    expect(chunks.length).toBe(1);
    expect(chunks[0]).toMatchObject({ index: 0, text: "hello world", contentHash: stableHash("hello world") });
  });

  it("splits long content into multiple ordered chunks", () => {
    const text = Array.from({ length: 200 }, () => "word").join(" ");
    const chunks = chunkText(text, 64);
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks.map((c) => c.index)).toEqual(chunks.map((_, i) => i));
    for (const chunk of chunks) {
      expect(chunk.text.length).toBeLessThanOrEqual(64 + chunk.text.length * 0);
      expect(chunk.contentHash).toBe(stableHash(chunk.text));
    }
  });
});