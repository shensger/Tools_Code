/**
 * Shared response-building helpers: markdown/JSON formatting, pagination footers,
 * truncation and error wrapping. Keeps every tool consistent and DRY.
 */

import { z } from "zod";
import { CHARACTER_LIMIT, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, ResponseFormat } from "../constants.js";
import type { CwRef, PagedResult } from "../types.js";
import { describeError } from "./client.js";

export interface ToolResult {
  [x: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

/* ------------------------------------------------------------------ */
/* Common Zod fragments                                                */
/* ------------------------------------------------------------------ */

export const responseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' (human-readable summary) or 'json' (complete raw API fields)");

export const paginationSchema = {
  page: z.number().int().min(1).default(1).describe("Page number (1-based)"),
  pageSize: z
    .number()
    .int()
    .min(1)
    .max(MAX_PAGE_SIZE)
    .default(DEFAULT_PAGE_SIZE)
    .describe(`Results per page (default ${DEFAULT_PAGE_SIZE}, max ${MAX_PAGE_SIZE})`),
};

export const conditionsDescription =
  `ConnectWise conditions filter string. Syntax: field operator value, joined with 'and'/'or'. ` +
  `Operators: = != < <= > >= contains like in not. Strings in double quotes, dates in brackets [2025-01-31T00:00:00Z]. ` +
  `Nested fields use '/', e.g. status/name="New" and board/id=1 and closedFlag=false and dateEntered>[2025-01-01T00:00:00Z]. ` +
  `Use 'in' for sets: status/name in ("New","In Progress"). Use 'like' with % wildcards: summary like "%VPN%".`;

export const orderByDescription =
  `Sort expression, e.g. "dateEntered desc", "priority/sortOrder asc", "id desc". Multiple: "board/name asc, id desc".`;

export const fieldsDescription =
  `Comma-separated list of fields to return (reduces payload), e.g. "id,summary,status/name,company/name". Leave empty for all fields.`;

export const listFilterSchema = {
  conditions: z.string().optional().describe(conditionsDescription),
  childConditions: z
    .string()
    .optional()
    .describe(`Filter on child collections, e.g. types/id=1 for company types. Same syntax as conditions.`),
  customFieldConditions: z
    .string()
    .optional()
    .describe(`Filter on custom fields, e.g. caption="Region" and value="West". Same syntax as conditions.`),
  orderBy: z.string().optional().describe(orderByDescription),
  fields: z.string().optional().describe(fieldsDescription),
  ...paginationSchema,
};

/* ------------------------------------------------------------------ */
/* Formatting helpers                                                  */
/* ------------------------------------------------------------------ */

/** "Name (#id)" for a CW reference object; "—" if missing. */
export function ref(r?: CwRef | null): string {
  if (!r) return "—";
  const label = r.name ?? r.identifier;
  const id = r.id !== undefined && r.id !== null ? `#${r.id}` : "";
  if (label && id) return `${label} (${id})`;
  return label ?? id ?? "—";
}

/** Human-readable timestamp (UTC), or "—". */
export function when(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z");
}

export function yesNo(v?: boolean | null): string {
  return v ? "yes" : "no";
}

export function hours(v?: number | null): string {
  return v === undefined || v === null ? "—" : `${Number(v).toFixed(2)}h`;
}

/** Truncate long free text for markdown display. */
export function clip(text: string | undefined | null, max = 400): string {
  if (!text) return "";
  const t = text.replace(/\r\n/g, "\n").trim();
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

/** Render a key/value block as markdown bullets, skipping empty values. */
export function kv(pairs: Array<[string, string | number | boolean | undefined | null]>): string {
  return pairs
    .filter(([, v]) => v !== undefined && v !== null && v !== "" && v !== "—")
    .map(([k, v]) => `- **${k}**: ${v}`)
    .join("\n");
}

/* ------------------------------------------------------------------ */
/* Result builders                                                     */
/* ------------------------------------------------------------------ */

function truncate(text: string): string {
  if (text.length <= CHARACTER_LIMIT) return text;
  return (
    text.slice(0, CHARACTER_LIMIT) +
    `\n\n…[truncated: response exceeded ${CHARACTER_LIMIT} characters. Use a smaller pageSize, the 'fields' parameter, or tighter 'conditions'.]`
  );
}

/** Build a tool result for a paginated list. */
export function listResult<T>(
  paged: PagedResult<T>,
  format: ResponseFormat,
  options: {
    title: string;
    itemKey: string;
    renderItem: (item: T) => string;
    emptyMessage?: string;
  },
): ToolResult {
  const structured: Record<string, unknown> = {
    total: paged.total,
    count: paged.count,
    page: paged.page,
    pageSize: paged.pageSize,
    has_more: paged.has_more,
    next_page: paged.next_page,
    [options.itemKey]: paged.items,
  };

  let text: string;
  if (format === ResponseFormat.JSON) {
    text = JSON.stringify(structured, null, 2);
  } else if (paged.count === 0) {
    text = options.emptyMessage ?? `No results for ${options.title}. Try loosening the 'conditions' filter.`;
  } else {
    const header = [
      `# ${options.title}`,
      paged.total !== undefined
        ? `Showing ${paged.count} of ${paged.total} (page ${paged.page}, pageSize ${paged.pageSize})`
        : `Showing ${paged.count} (page ${paged.page}, pageSize ${paged.pageSize})`,
      "",
    ];
    const body = paged.items.map(options.renderItem);
    const footer = paged.has_more ? ["", `_More results available — request page ${paged.next_page}._`] : [];
    text = [...header, ...body, ...footer].join("\n");
  }

  return { content: [{ type: "text", text: truncate(text) }], structuredContent: structured };
}

/** Build a tool result for a single record. */
export function recordResult<T extends object>(
  record: T,
  format: ResponseFormat,
  renderMarkdown: (item: T) => string,
): ToolResult {
  const text = format === ResponseFormat.JSON ? JSON.stringify(record, null, 2) : renderMarkdown(record);
  return {
    content: [{ type: "text", text: truncate(text) }],
    structuredContent: record as unknown as Record<string, unknown>,
  };
}

/** Plain text result (e.g. confirmations). */
export function textResult(text: string, structured?: Record<string, unknown>): ToolResult {
  return { content: [{ type: "text", text: truncate(text) }], structuredContent: structured };
}

/** Error result — reported inside the tool result, not as a protocol error. */
export function errorResult(error: unknown): ToolResult {
  return { isError: true, content: [{ type: "text", text: describeError(error) }] };
}

/** Wrap a handler so any thrown error becomes an errorResult. */
export function safe<A>(fn: (args: A) => Promise<ToolResult>): (args: A) => Promise<ToolResult> {
  return async (args: A) => {
    try {
      return await fn(args);
    } catch (e) {
      return errorResult(e);
    }
  };
}

/** Build a reference object from an optional id or name/identifier; CW resolves names server-side. */
export function nameRef(id?: number, name?: string, key: "name" | "identifier" = "name"): Record<string, unknown> | undefined {
  if (id !== undefined) return { id };
  if (name) return { [key]: name };
  return undefined;
}
