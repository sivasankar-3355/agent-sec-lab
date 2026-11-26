import { describe, expect, it } from "vitest";
import {
  derivedMemoryTrust,
  isMemoryExpired,
  isWritableMemorySource,
  limitMemoryContent,
  MEMORY_LIMITS,
  MEMORY_RETENTION_SECONDS,
  memoryCollectionFor,
  memorySnippet,
  memoryStatusFor,
  memoryTypeFor,
  retentionSecondsFor,
} from "../../src/core/memory.js";

describe("memory model", () => {
  it("derives trust from provenance and never trusts application sources", () => {
    expect(derivedMemoryTrust("system")).toBe("trusted");
    expect(derivedMemoryTrust("user")).toBe("untrusted");
    expect(derivedMemoryTrust("external_document")).toBe("untrusted");
    expect(derivedMemoryTrust("tool_output")).toBe("untrusted");
    expect(derivedMemoryTrust("agent_output")).toBe("untrusted");
  });

  it("only allows non-system sources to be written", () => {
    expect(isWritableMemorySource("user")).toBe(true);
    expect(isWritableMemorySource("external_document")).toBe(true);
    expect(isWritableMemorySource("tool_output")).toBe(true);
    expect(isWritableMemorySource("agent_output")).toBe(true);
    expect(isWritableMemorySource("system")).toBe(false);
    expect(isWritableMemorySource("other")).toBe(false);
  });

  it("derives a code-owned collection per source", () => {
    expect(memoryCollectionFor("user")).toBe("user-notes");
    expect(memoryCollectionFor("external_document")).toBe("document-notes");
    expect(memoryCollectionFor("tool_output")).toBe("tool-notes");
    expect(memoryCollectionFor("agent_output")).toBe("agent-notes");
    expect(memoryCollectionFor("system")).toBe("system");
  });

  it("derives a code-owned memory type and status", () => {
    expect(memoryTypeFor("user")).toBe("user-note");
    expect(memoryTypeFor("external_document")).toBe("document-context");
    expect(memoryTypeFor("tool_output")).toBe("tool-observation");
    expect(memoryTypeFor("agent_output")).toBe("agent-context");
    expect(memoryTypeFor("system")).toBe("system");
    expect(memoryStatusFor(false)).toBe("active");
    expect(memoryStatusFor(true)).toBe("conflicted");
  });

  it("clamps requested retention to the source-type maximum", () => {
    expect(retentionSecondsFor("tool_output")).toBe(MEMORY_RETENTION_SECONDS.tool_output);
    expect(retentionSecondsFor("tool_output", MEMORY_RETENTION_SECONDS.user)).toBe(
      MEMORY_RETENTION_SECONDS.tool_output,
    );
    expect(retentionSecondsFor("user", 1)).toBe(MEMORY_LIMITS.minTtlSeconds);
    expect(retentionSecondsFor("user", MEMORY_RETENTION_SECONDS.user / 2)).toBe(
      MEMORY_RETENTION_SECONDS.user / 2,
    );
  });

  it("bounds stored content and search snippets", () => {
    const long = "x".repeat(MEMORY_LIMITS.maxContentChars + 100);
    expect(limitMemoryContent(long).length).toBeLessThanOrEqual(MEMORY_LIMITS.maxContentChars + 32);
    expect(limitMemoryContent(long).endsWith("[memory truncated]")).toBe(true);

    const snippet = memorySnippet("y".repeat(MEMORY_LIMITS.maxSnippetChars + 10));
    expect(snippet.truncated).toBe(true);
    expect(snippet.content.length).toBe(MEMORY_LIMITS.maxSnippetChars);
    expect(memorySnippet("short").truncated).toBe(false);
  });

  it("treats expired and malformed expiries as expired", () => {
    expect(isMemoryExpired({})).toBe(false);
    expect(isMemoryExpired({ expiresAt: new Date(Date.now() - 1000).toISOString() })).toBe(true);
    expect(isMemoryExpired({ expiresAt: new Date(Date.now() + 60_000).toISOString() })).toBe(false);
    expect(isMemoryExpired({ expiresAt: "not-a-date" })).toBe(true);
  });
});
