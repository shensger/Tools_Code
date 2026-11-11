import { CHARACTER_LIMIT } from "../constants.js";

export enum ResponseFormat {
  MARKDOWN = "markdown",
  JSON = "json",
}

/** Standard MCP tool result shape - index signature satisfies SDK's CallToolResult */
export interface ToolResult {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
}

/** Wrap text as a tool result */
export function textResult(text: string): ToolResult {
  return { content: [{ type: "text", text }] };
}

/** Serialize data to JSON and truncate if needed */
export function jsonResult(data: unknown): ToolResult {
  let text = JSON.stringify(data, null, 2);
  if (text.length > CHARACTER_LIMIT) {
    text =
      "[Response truncated - too large. Use pagination parameters (pageSize/after) or add filters.]\n\n" +
      text.slice(0, CHARACTER_LIMIT) +
      "...";
  }
  return textResult(text);
}

/** Format a Unix timestamp (seconds) as ISO string, or N/A */
export function fmtTs(ts: number | undefined | null): string {
  if (ts == null) return "N/A";
  return new Date(ts * 1000).toISOString();
}

/** Format a date string or N/A */
export function fmtDate(d: string | undefined | null): string {
  return d != null ? d : "N/A";
}

/** Build a pagination note string */
export function paginationNote(hasMore: boolean, lastCursor?: number | string): string {
  if (!hasMore) return "";
  const cursor = lastCursor !== undefined ? " (after=" + String(lastCursor) + ")" : "";
  return "\n> More results available" + cursor + ". Pass 'after' parameter to get next page.";
}

/** Build a pagination note string for cursor-based (string cursor) endpoints */
export function cursorPaginationNote(hasMore: boolean, nextCursor?: string): string {
  if (!hasMore) return "";
  const cursor = nextCursor ? ` (cursor="${nextCursor}")` : "";
  return "\n> More results available" + cursor + ". Pass 'cursor' parameter to get next page.";
}

/**
 * Unwrap a NinjaOne cursor-paginated response, which may come back either as a
 * bare array or as `{ results: T[], cursor?: string }` depending on endpoint/version.
 */
export function unwrapCursorPage<T>(result: { results?: T[]; cursor?: string } | T[]): {
  entries: T[];
  nextCursor: string | undefined;
} {
  if (Array.isArray(result)) return { entries: result, nextCursor: undefined };
  return { entries: result.results ?? [], nextCursor: result.cursor };
}

/**
 * Render a list of flat record objects as a compact markdown bullet list.
 * Each entry shows the given fields in "Label: value" form, skipping null/undefined.
 * Intended for fleet-wide query endpoints whose shape is a simple flat report row.
 */
export function recordListMarkdown(
  title: string,
  entries: Array<Record<string, unknown>>,
  fields: Array<{ key: string; label: string }>
): string {
  const lines = [`# ${title} (${entries.length})`, ""];
  for (const e of entries) {
    const parts = fields
      .map(({ key, label }) => {
        const v = e[key];
        if (v === undefined || v === null || v === "") return null;
        return `${label}: ${String(v)}`;
      })
      .filter((p): p is string => p !== null);
    lines.push(`- ${parts.join(" | ")}`);
  }
  return lines.join("\n");
}
