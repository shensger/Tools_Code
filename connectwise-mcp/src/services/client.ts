/**
 * ConnectWise Manage REST API client.
 *
 * Authentication: HTTP Basic with username "<companyId>+<publicKey>" and password "<privateKey>",
 * plus the mandatory "clientId" header (register one at https://developer.connectwise.com).
 *
 * Environment variables:
 *   CW_SITE         API host, e.g. "api-na.myconnectwise.net", "api-eu.myconnectwise.net",
 *                   "api-au.myconnectwise.net", "api-staging.connectwisedev.com", or your on-prem host.
 *                   (Bare "na.myconnectwise.net" is accepted and auto-prefixed with "api-".)
 *   CW_COMPANY_ID   Your ConnectWise company ID (the one you log in with).
 *   CW_PUBLIC_KEY   API member public key.
 *   CW_PRIVATE_KEY  API member private key.
 *   CW_CLIENT_ID    Developer clientId GUID.
 *   CW_CODEBASE     Optional. Defaults to "v4_6_release". Older on-prem installs may need "v2019_5" etc.
 *   CW_API_VERSION  Optional. Sent as Accept version, defaults to "2025.1".
 */

import { REQUEST_TIMEOUT_MS, MAX_PAGE_SIZE } from "../constants.js";
import type { CwError, PagedResult, PatchOp } from "../types.js";

export interface CwConfig {
  site: string;
  scheme: "http" | "https";
  companyId: string;
  publicKey: string;
  privateKey: string;
  clientId: string;
  codebase: string;
  apiVersion: string;
}

export interface ListParams {
  conditions?: string;
  childConditions?: string;
  customFieldConditions?: string;
  orderBy?: string;
  fields?: string;
  page?: number;
  pageSize?: number;
}

export class CwApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly method: string,
    public readonly path: string,
    public readonly body: CwError | string | undefined,
    public readonly retryAfterMs?: number,
  ) {
    super(`ConnectWise API ${method} ${path} failed with HTTP ${status}`);
    this.name = "CwApiError";
  }
}

let cachedConfig: CwConfig | undefined;

export function loadConfig(): CwConfig {
  if (cachedConfig) return cachedConfig;

  const required = ["CW_SITE", "CW_COMPANY_ID", "CW_PUBLIC_KEY", "CW_PRIVATE_KEY", "CW_CLIENT_ID"] as const;
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    throw new Error(
      `Missing required environment variable(s): ${missing.join(", ")}. ` +
        `Set CW_SITE (e.g. api-na.myconnectwise.net), CW_COMPANY_ID, CW_PUBLIC_KEY, CW_PRIVATE_KEY and CW_CLIENT_ID.`,
    );
  }

  const rawSite = process.env.CW_SITE!.trim().replace(/\/+$/, "");
  const scheme = /^http:\/\//i.test(rawSite) ? "http" : "https"; // http only for local mocks / test servers
  let site = rawSite.replace(/^https?:\/\//i, "");
  // Convenience: "na.myconnectwise.net" -> "api-na.myconnectwise.net"
  if (/^(na|eu|au|aus|staging)\.myconnectwise\.net$/i.test(site)) site = `api-${site}`;

  cachedConfig = {
    site,
    scheme,
    companyId: process.env.CW_COMPANY_ID!.trim(),
    publicKey: process.env.CW_PUBLIC_KEY!.trim(),
    privateKey: process.env.CW_PRIVATE_KEY!.trim(),
    clientId: process.env.CW_CLIENT_ID!.trim(),
    codebase: (process.env.CW_CODEBASE || "v4_6_release").replace(/^\/+|\/+$/g, ""),
    apiVersion: process.env.CW_API_VERSION || "2025.1",
  };
  return cachedConfig;
}

function baseUrl(cfg: CwConfig): string {
  return `${cfg.scheme}://${cfg.site}/${cfg.codebase}/apis/3.0`;
}

function authHeader(cfg: CwConfig): string {
  const token = Buffer.from(`${cfg.companyId}+${cfg.publicKey}:${cfg.privateKey}`).toString("base64");
  return `Basic ${token}`;
}

type Query = Record<string, string | number | boolean | undefined>;

function buildUrl(cfg: CwConfig, path: string, query?: Query): string {
  const url = new URL(`${baseUrl(cfg)}/${path.replace(/^\/+/, "")}`);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

interface RawResponse<T> {
  data: T;
  headers: Headers;
  status: number;
}

const MAX_429_RETRIES = 3;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Wraps the single request with automatic retry on HTTP 429 (ConnectWise rate limit, ~60 req/min
 * per API member). Honors Retry-After when present, otherwise backs off 2s/4s/8s.
 * A 429 means the request was rejected before processing, so retrying non-GET methods is safe too.
 */
async function rawRequest<T>(
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  options: { query?: Query; body?: unknown } = {},
): Promise<RawResponse<T>> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await rawRequestOnce<T>(method, path, options);
    } catch (e) {
      if (!(e instanceof CwApiError) || e.status !== 429 || attempt >= MAX_429_RETRIES) throw e;
      const wait = e.retryAfterMs ?? 2000 * 2 ** attempt;
      console.error(`ConnectWise 429 on ${method} ${path}; retrying in ${wait}ms (attempt ${attempt + 1}/${MAX_429_RETRIES})`);
      await sleep(wait);
    }
  }
}

async function rawRequestOnce<T>(
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  options: { query?: Query; body?: unknown } = {},
): Promise<RawResponse<T>> {
  const cfg = loadConfig();
  const url = buildUrl(cfg, path, options.query);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: authHeader(cfg),
        clientId: cfg.clientId,
        Accept: `application/vnd.connectwise.com+json; version=${cfg.apiVersion}`,
        "Content-Type": "application/json",
      },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });

    const text = await res.text();
    let parsed: unknown = undefined;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }

    if (!res.ok) {
      const ra = Number(res.headers.get("retry-after"));
      const retryAfterMs = Number.isFinite(ra) && ra > 0 ? Math.min(ra, 60) * 1000 : undefined;
      throw new CwApiError(res.status, method, path, parsed as CwError | string | undefined, retryAfterMs);
    }

    return { data: parsed as T, headers: res.headers, status: res.status };
  } finally {
    clearTimeout(timer);
  }
}

/** GET a single resource. */
export async function cwGet<T>(path: string, query?: Query): Promise<T> {
  return (await rawRequest<T>("GET", path, { query })).data;
}

/** POST (create). */
export async function cwPost<T>(path: string, body: unknown): Promise<T> {
  return (await rawRequest<T>("POST", path, { body })).data;
}

/** PUT (full replace). */
export async function cwPut<T>(path: string, body: unknown): Promise<T> {
  return (await rawRequest<T>("PUT", path, { body })).data;
}

/** PATCH with JSON Patch operations. */
export async function cwPatch<T>(path: string, ops: PatchOp[]): Promise<T> {
  return (await rawRequest<T>("PATCH", path, { body: ops })).data;
}

/** DELETE. */
export async function cwDelete(path: string): Promise<void> {
  await rawRequest<unknown>("DELETE", path);
}

/** GET a /count endpoint. */
export async function cwCount(path: string, conditions?: string, extra?: Query): Promise<number> {
  const res = await cwGet<{ count: number }>(`${path.replace(/\/+$/, "")}/count`, { conditions, ...extra });
  return res?.count ?? 0;
}

/**
 * GET a paginated list. Uses the "Link" response header (rel="next") to detect further pages.
 * Optionally fetches the /count endpoint for a total.
 */
export async function cwList<T>(
  path: string,
  params: ListParams = {},
  options: { includeTotal?: boolean } = {},
): Promise<PagedResult<T>> {
  const page = Math.max(1, params.page ?? 1);
  const pageSize = Math.min(MAX_PAGE_SIZE, Math.max(1, params.pageSize ?? 25));

  const query: Query = {
    conditions: params.conditions,
    childConditions: params.childConditions,
    customFieldConditions: params.customFieldConditions,
    orderBy: params.orderBy,
    fields: params.fields,
    page,
    pageSize,
  };

  const res = await rawRequest<T[]>("GET", path, { query });
  const items = Array.isArray(res.data) ? res.data : [];
  const link = res.headers.get("link") ?? "";
  const has_more = /rel="next"/i.test(link);

  let total: number | undefined;
  if (options.includeTotal) {
    try {
      total = await cwCount(path, params.conditions, {
        childConditions: params.childConditions,
        customFieldConditions: params.customFieldConditions,
      });
    } catch {
      /* count endpoints don't exist for every resource; ignore */
    }
  }

  const more = has_more || (total !== undefined && total > (page - 1) * pageSize + items.length);

  return {
    items,
    page,
    pageSize,
    count: items.length,
    has_more: more,
    next_page: more ? page + 1 : undefined,
    total,
  };
}

/** Build a JSON Patch "replace" op list from a flat object of field -> value (undefined values skipped). */
export function toPatchOps(fields: Record<string, unknown>): PatchOp[] {
  return Object.entries(fields)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => ({ op: "replace" as const, path: `/${k}`, value: v }));
}

/** Convert an API error into a helpful, actionable message for the agent. */
export function describeError(error: unknown): string {
  if (error instanceof CwApiError) {
    const body = error.body;
    let detail = "";
    if (body && typeof body === "object") {
      const parts: string[] = [];
      if (body.message) parts.push(body.message);
      for (const e of body.errors ?? []) {
        parts.push([e.field, e.message].filter(Boolean).join(": "));
      }
      detail = parts.filter(Boolean).join(" | ");
    } else if (typeof body === "string" && body.trim()) {
      detail = body.slice(0, 500);
    }

    switch (error.status) {
      case 400:
        return `Error 400 (bad request) on ${error.method} ${error.path}: ${detail || "invalid input"}. Check the 'conditions' syntax (e.g. status/name="New" and board/id=1) and that referenced IDs/names exist.`;
      case 401:
        return `Error 401 (unauthorized): ConnectWise rejected the credentials. Verify CW_COMPANY_ID, CW_PUBLIC_KEY, CW_PRIVATE_KEY and that CW_CLIENT_ID is a valid registered clientId. ${detail}`.trim();
      case 403:
        return `Error 403 (forbidden) on ${error.method} ${error.path}: the API member's security role lacks permission for this action. ${detail}`.trim();
      case 404:
        return `Error 404 (not found) on ${error.method} ${error.path}: ${detail || "no record with that ID, or the endpoint is wrong for this codebase (CW_CODEBASE)."}`;
      case 409:
        return `Error 409 (conflict) on ${error.method} ${error.path}: ${detail}`;
      case 429:
        return `Error 429: ConnectWise rate limit hit. Wait a moment and retry with smaller pageSize or fewer calls.`;
      default:
        return `Error ${error.status} on ${error.method} ${error.path}: ${detail || "request failed"}`;
    }
  }
  if (error instanceof Error) {
    if (error.name === "AbortError") return `Error: request to ConnectWise timed out after ${REQUEST_TIMEOUT_MS / 1000}s.`;
    if (/ENOTFOUND|ECONNREFUSED|EAI_AGAIN/.test(error.message)) {
      return `Error: cannot reach ConnectWise host. Check CW_SITE (e.g. api-na.myconnectwise.net) and network access. (${error.message})`;
    }
    return `Error: ${error.message}`;
  }
  return `Error: ${String(error)}`;
}
