import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, cursorPaginationNote, unwrapCursorPage, fmtDate, ResponseFormat } from "../services/response-utils.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../constants.js";
import type {
  SoftwareEntry,
  OsPatchEntry,
  OsPatchInstallEntry,
  SoftwarePatchEntry,
  SoftwarePatchInstallEntry,
  DeviceHealthEntry,
  AntivirusStatusEntry,
  AntivirusThreatEntry,
  OperatingSystemEntry,
  ComputerSystemEntry,
  LoggedOnUserEntry,
} from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

const DeviceFilterField = z
  .string()
  .optional()
  .describe('NinjaOne device filter expression to scope devices, e.g. "organization = 5" or "class = WINDOWS_SERVER"');

const severityIcon = (sev: string | undefined) =>
  sev === "CRITICAL" ? "🔴" : sev === "IMPORTANT" ? "🟠" : sev === "MODERATE" ? "🟡" : "⚪";

export function registerQueryTools(server: McpServer): void {
  // ── Query Software (fleet-wide) ────────────────────────────────────────────

  server.registerTool(
    "ninjaone_query_software",
    {
      title: "Query Software Inventory (Fleet-Wide)",
      description: `Query the software inventory across devices in NinjaOne.

Useful for auditing installed applications, finding a specific software across all endpoints, or
building a software inventory report. To scope by organization, use device_filter (e.g.
"organization = 5") — NinjaOne's software query itself has no organization/name parameter, so a
name filter is applied client-side on top of the API response.

Args:
  - device_filter (string, optional): NinjaOne device filter expression, e.g. "organization = 5"
  - name (string, optional): Client-side filter — only entries whose name contains this text
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor from previous response
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')

Returns device ID, software name, publisher, version, and install date.`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        name: z.string().optional().describe("Client-side filter: only entries whose name contains this text"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor from previous response"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, name, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: SoftwareEntry[]; cursor?: string } | SoftwareEntry[]>("/queries/software", params);
        let { entries, nextCursor } = unwrapCursorPage(result);
        if (name) {
          const needle = name.toLowerCase();
          entries = entries.filter((s) => (s.name ?? "").toLowerCase().includes(needle));
        }

        if (!entries.length) return textResult("No software entries found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, software: entries });
        }

        const lines = [`# Software Inventory (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const s of entries) {
          lines.push(`- **${s.name ?? "Unknown"}** v${s.version ?? "?"} — Publisher: ${s.publisher ?? "N/A"} | Device: ${s.deviceId} | Installed: ${fmtDate(s.installDate)}`);
        }
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query OS Patches (fleet-wide) ──────────────────────────────────────────

  server.registerTool(
    "ninjaone_query_os_patches",
    {
      title: "Query OS Patch Status (Fleet-Wide)",
      description: `Query pending/failed/rejected OS patches across devices — patch compliance reporting,
finding devices missing critical patches. For already-installed patches, use
ninjaone_query_os_patch_installs. For one device, use ninjaone_get_device_os_patches.

Args:
  - device_filter (string, optional): NinjaOne device filter expression, e.g. "organization = 5"
  - status (string, optional): Filter by patch status, e.g. 'FAILED', 'PENDING', 'APPROVED', 'REJECTED'
  - severity (string, optional): Filter by severity: 'CRITICAL', 'IMPORTANT', 'MODERATE', 'LOW', 'OPTIONAL'
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor from previous response
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        status: z.string().optional().describe("Filter by status: FAILED, PENDING, APPROVED, REJECTED"),
        severity: z.string().optional().describe("Filter by severity: CRITICAL, IMPORTANT, MODERATE, LOW, OPTIONAL"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor from previous response"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, status, severity, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (status) params["status"] = status;
        if (severity) params["severity"] = severity;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: OsPatchEntry[]; cursor?: string } | OsPatchEntry[]>("/queries/os-patches", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No patch entries found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, patches: entries });
        }

        const lines = [`# OS Patches Needing Attention (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const p of entries) {
          lines.push(`- ${severityIcon(p.severity)} **${p.name ?? "Unknown"}** (${p.kbNumber ?? "N/A"}) — Status: ${p.status ?? "N/A"} | Device: ${p.deviceId}`);
        }
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query OS Patch Installs (fleet-wide) ───────────────────────────────────

  server.registerTool(
    "ninjaone_query_os_patch_installs",
    {
      title: "Query OS Patch Install History (Fleet-Wide)",
      description: `Query the history of OS patches already installed, across devices.

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - status (string, optional): Filter by install status
  - installed_after (string, optional): ISO date
  - installed_before (string, optional): ISO date
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        status: z.string().optional().describe("Filter by install status"),
        installed_after: z.string().optional().describe("ISO date"),
        installed_before: z.string().optional().describe("ISO date"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, status, installed_after, installed_before, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (status) params["status"] = status;
        if (installed_after) params["installedAfter"] = installed_after;
        if (installed_before) params["installedBefore"] = installed_before;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: OsPatchInstallEntry[]; cursor?: string } | OsPatchInstallEntry[]>("/queries/os-patch-installs", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No OS patch install history found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, patches: entries });
        }
        const lines = [`# OS Patch Install History (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const p of entries) {
          lines.push(`- **${p.name ?? "Unknown"}** (${p.kbNumber ?? "N/A"}) — ${p.status ?? "N/A"} — Device: ${p.deviceId} — installed ${fmtDate(p.installedAt)}`);
        }
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query Software Patches (fleet-wide) ────────────────────────────────────

  server.registerTool(
    "ninjaone_query_software_patches",
    {
      title: "Query Software Patch Status (Fleet-Wide)",
      description: `Query pending/failed/rejected third-party software patches across devices (browser, Java,
Adobe, etc. — not OS patches).

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - status (string, optional): Filter by status
  - product_identifier (string, optional): Filter to one product
  - impact (string, optional): Filter by impact level
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        status: z.string().optional().describe("Filter by status"),
        product_identifier: z.string().optional().describe("Filter to one product identifier"),
        impact: z.string().optional().describe("Filter by impact level"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, status, product_identifier, impact, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (status) params["status"] = status;
        if (product_identifier) params["productIdentifier"] = product_identifier;
        if (impact) params["impact"] = impact;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: SoftwarePatchEntry[]; cursor?: string } | SoftwarePatchEntry[]>("/queries/software-patches", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No software patch entries found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, patches: entries });
        }
        const lines = [`# Software Patches Needing Attention (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const p of entries) {
          lines.push(`- **${p.name ?? p.productIdentifier ?? "Unknown"}** — ${p.status ?? "N/A"} — impact: ${p.impact ?? "N/A"} — Device: ${p.deviceId}`);
        }
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query Software Patch Installs (fleet-wide) ─────────────────────────────

  server.registerTool(
    "ninjaone_query_software_patch_installs",
    {
      title: "Query Software Patch Install History (Fleet-Wide)",
      description: `Query the history of already-installed third-party software patches across devices.

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - status (string, optional): Filter by install status
  - product_identifier (string, optional): Filter to one product
  - installed_after (string, optional): ISO date
  - installed_before (string, optional): ISO date
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        status: z.string().optional().describe("Filter by install status"),
        product_identifier: z.string().optional().describe("Filter to one product identifier"),
        installed_after: z.string().optional().describe("ISO date"),
        installed_before: z.string().optional().describe("ISO date"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, status, product_identifier, installed_after, installed_before, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (status) params["status"] = status;
        if (product_identifier) params["productIdentifier"] = product_identifier;
        if (installed_after) params["installedAfter"] = installed_after;
        if (installed_before) params["installedBefore"] = installed_before;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: SoftwarePatchInstallEntry[]; cursor?: string } | SoftwarePatchInstallEntry[]>(
          "/queries/software-patch-installs",
          params
        );
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No software patch install history found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, patches: entries });
        }
        const lines = [`# Software Patch Install History (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const p of entries) {
          lines.push(`- **${p.name ?? p.productIdentifier ?? "Unknown"}** — ${p.status ?? "N/A"} — Device: ${p.deviceId} — installed ${fmtDate(p.installedAt)}`);
        }
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query Device Health ─────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_query_device_health",
    {
      title: "Query Device Health Report",
      description: `Query NinjaOne's overall health status/score across devices — a quick way to find
devices that need attention without checking each one individually.

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - health (string, optional): Filter by health status
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        health: z.string().optional().describe("Filter by health status"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, health, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (health) params["health"] = health;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: DeviceHealthEntry[]; cursor?: string } | DeviceHealthEntry[]>("/queries/device-health", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No device health entries found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, health: entries });
        }
        const lines = [`# Device Health (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const h of entries) lines.push(`- Device ${h.deviceId} — ${h.health ?? "N/A"}${h.score !== undefined ? ` (score: ${h.score})` : ""}`);
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query Antivirus Status ──────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_query_antivirus_status",
    {
      title: "Query Antivirus Status",
      description: `Query the antivirus product status across devices — useful for finding devices with AV
disabled, out of date, or otherwise unhealthy. For actual detected threats, use
ninjaone_query_antivirus_threats.

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - product_state (string, optional): Filter by product state
  - product_name (string, optional): Filter by AV product name
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        product_state: z.string().optional().describe("Filter by product state"),
        product_name: z.string().optional().describe("Filter by AV product name"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, product_state, product_name, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (product_state) params["productState"] = product_state;
        if (product_name) params["productName"] = product_name;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: AntivirusStatusEntry[]; cursor?: string } | AntivirusStatusEntry[]>("/queries/antivirus-status", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No antivirus status entries found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, antivirus: entries });
        }
        const lines = [`# Antivirus Status (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const a of entries) lines.push(`- Device ${a.deviceId} — **${a.productName ?? "Unknown"}** — ${a.productState ?? "N/A"}`);
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query Antivirus Threats ─────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_query_antivirus_threats",
    {
      title: "Query Antivirus Threats",
      description: `Query detected antivirus threats/malware findings across devices.

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: AntivirusThreatEntry[]; cursor?: string } | AntivirusThreatEntry[]>("/queries/antivirus-threats", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No antivirus threats found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, threats: entries });
        }
        const lines = [`# Antivirus Threats (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const t of entries) lines.push(`- 🦠 Device ${t.deviceId} — **${t.name ?? "Unknown threat"}** — ${t.threatStatus ?? "N/A"} — found ${fmtDate(t.foundDate)}`);
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query Operating Systems ──────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_query_operating_systems",
    {
      title: "Query Operating Systems (Fleet-Wide)",
      description: `Query OS details (name, manufacturer, architecture, build) across devices — handy for OS
version audits.

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: OperatingSystemEntry[]; cursor?: string } | OperatingSystemEntry[]>("/queries/operating-systems", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No operating system entries found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, operating_systems: entries });
        }
        const lines = [`# Operating Systems (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const o of entries) lines.push(`- Device ${o.deviceId} — **${o.name ?? "Unknown"}** (${o.architecture ?? "N/A"}, build ${o.buildNumber ?? "N/A"})`);
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query Computer Systems ───────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_query_computer_systems",
    {
      title: "Query Computer Systems (Fleet-Wide)",
      description: `Query hardware/system details (manufacturer, model, serial number) across devices — handy
for asset/warranty audits.

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: ComputerSystemEntry[]; cursor?: string } | ComputerSystemEntry[]>("/queries/computer-systems", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No computer system entries found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, systems: entries });
        }
        const lines = [`# Computer Systems (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const s of entries) lines.push(`- Device ${s.deviceId} — **${s.manufacturer ?? "?"} ${s.model ?? "?"}** — S/N: ${s.biosSerialNumber ?? "N/A"}`);
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Query Logged-On Users ────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_query_logged_on_users",
    {
      title: "Query Logged-On Users (Fleet-Wide)",
      description: `Query which user is currently/last logged into each device — useful for finding who's using
a given machine across the whole fleet at once.

Args:
  - device_filter (string, optional): NinjaOne device filter expression
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - cursor (string, optional): Pagination cursor
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: DeviceFilterField,
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        cursor: z.string().optional().describe("Pagination cursor"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (device_filter) params["df"] = device_filter;
        if (cursor) params["cursor"] = cursor;

        const result = await client.get<{ results?: LoggedOnUserEntry[]; cursor?: string } | LoggedOnUserEntry[]>("/queries/logged-on-users", params);
        const { entries, nextCursor } = unwrapCursorPage(result);
        if (!entries.length) return textResult("No logged-on-user entries found matching filters.");
        const hasMore = nextCursor !== undefined;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: entries.length, has_more: hasMore, next_cursor: nextCursor, users: entries });
        }
        const lines = [`# Logged-On Users (${entries.length}${hasMore ? "+" : ""})`, ""];
        for (const u of entries) lines.push(`- Device ${u.deviceId} — **${u.userName ?? "(none)"}**`);
        lines.push(cursorPaginationNote(hasMore, nextCursor));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
