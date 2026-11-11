import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, fmtDate, ResponseFormat } from "../services/response-utils.js";
import type { OsPatchEntry, OsPatchInstallEntry, SoftwarePatchEntry, SoftwarePatchInstallEntry } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

const severityIcon = (sev: string | undefined) =>
  sev === "CRITICAL" ? "🔴" : sev === "IMPORTANT" ? "🟠" : sev === "MODERATE" ? "🟡" : "⚪";

export function registerDevicePatchingTools(server: McpServer): void {
  // ── Device OS Patches (pending/failed/rejected) ────────────────────────────

  server.registerTool(
    "ninjaone_get_device_os_patches",
    {
      title: "Get Device OS Patch Status",
      description: `Get pending, failed, and rejected OS patches for one device — i.e. what still needs
attention. For patches already installed, use ninjaone_get_device_os_patch_installs. For a
fleet-wide view across many devices, use ninjaone_query_os_patches.

Args:
  - device_id (number): The device ID
  - status (string, optional): Filter by status, e.g. 'FAILED', 'PENDING', 'APPROVED', 'REJECTED'
  - severity (string, optional): Filter by severity: 'CRITICAL', 'IMPORTANT', 'MODERATE', 'LOW', 'OPTIONAL'
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        status: z.string().optional().describe("Filter by status"),
        severity: z.string().optional().describe("Filter by severity"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, status, severity, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = {};
        if (status) params["status"] = status;
        if (severity) params["severity"] = severity;

        const patches = await client.get<OsPatchEntry[]>(`/device/${device_id}/os-patches`, params);
        if (!patches.length) return textResult(`No pending/failed/rejected OS patches for device ${device_id}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: patches.length, patches });

        const lines = [`# OS Patches Needing Attention — Device ${device_id} (${patches.length})`, ""];
        for (const p of patches) {
          lines.push(`- ${severityIcon(p.severity)} **${p.name ?? "Unknown"}** (${p.kbNumber ?? "N/A"}) — ${p.status ?? "N/A"}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Device OS Patch Installs (history) ─────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device_os_patch_installs",
    {
      title: "Get Device OS Patch Install History",
      description: `Get the history of OS patches already installed on one device.

Args:
  - device_id (number): The device ID
  - status (string, optional): Filter by install status
  - installed_after (string, optional): ISO date — only patches installed after this date
  - installed_before (string, optional): ISO date — only patches installed before this date
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        status: z.string().optional().describe("Filter by install status"),
        installed_after: z.string().optional().describe("ISO date, e.g. '2026-01-01'"),
        installed_before: z.string().optional().describe("ISO date, e.g. '2026-06-01'"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, status, installed_after, installed_before, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = {};
        if (status) params["status"] = status;
        if (installed_after) params["installedAfter"] = installed_after;
        if (installed_before) params["installedBefore"] = installed_before;

        const patches = await client.get<OsPatchInstallEntry[]>(`/device/${device_id}/os-patch-installs`, params);
        if (!patches.length) return textResult(`No OS patch install history for device ${device_id} matching filters.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: patches.length, patches });

        const lines = [`# OS Patch Install History — Device ${device_id} (${patches.length})`, ""];
        for (const p of patches) {
          lines.push(`- **${p.name ?? "Unknown"}** (${p.kbNumber ?? "N/A"}) — ${p.status ?? "N/A"} — installed ${fmtDate(p.installedAt)}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Device Software Patches (pending/failed/rejected) ──────────────────────

  server.registerTool(
    "ninjaone_get_device_software_patches",
    {
      title: "Get Device Software Patch Status",
      description: `Get pending, failed, and rejected third-party software patches for one device (e.g. browser,
Java, Adobe updates — not OS patches). For a fleet-wide view, use ninjaone_query_software_patches.

Args:
  - device_id (number): The device ID
  - status (string, optional): Filter by status
  - product_identifier (string, optional): Filter to one product
  - impact (string, optional): Filter by impact level
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        status: z.string().optional().describe("Filter by status"),
        product_identifier: z.string().optional().describe("Filter to one product identifier"),
        impact: z.string().optional().describe("Filter by impact level"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, status, product_identifier, impact, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = {};
        if (status) params["status"] = status;
        if (product_identifier) params["productIdentifier"] = product_identifier;
        if (impact) params["impact"] = impact;

        const patches = await client.get<SoftwarePatchEntry[]>(`/device/${device_id}/software-patches`, params);
        if (!patches.length) return textResult(`No pending/failed/rejected software patches for device ${device_id}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: patches.length, patches });

        const lines = [`# Software Patches Needing Attention — Device ${device_id} (${patches.length})`, ""];
        for (const p of patches) {
          lines.push(`- **${p.name ?? p.productIdentifier ?? "Unknown"}** — ${p.status ?? "N/A"} — impact: ${p.impact ?? "N/A"}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Device Software Patch Installs (history) ───────────────────────────────

  server.registerTool(
    "ninjaone_get_device_software_patch_installs",
    {
      title: "Get Device Software Patch Install History",
      description: `Get the history of third-party software patches already installed on one device.

Args:
  - device_id (number): The device ID
  - status (string, optional): Filter by install status
  - product_identifier (string, optional): Filter to one product
  - installed_after (string, optional): ISO date
  - installed_before (string, optional): ISO date
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        status: z.string().optional().describe("Filter by install status"),
        product_identifier: z.string().optional().describe("Filter to one product identifier"),
        installed_after: z.string().optional().describe("ISO date"),
        installed_before: z.string().optional().describe("ISO date"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, status, product_identifier, installed_after, installed_before, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = {};
        if (status) params["status"] = status;
        if (product_identifier) params["productIdentifier"] = product_identifier;
        if (installed_after) params["installedAfter"] = installed_after;
        if (installed_before) params["installedBefore"] = installed_before;

        const patches = await client.get<SoftwarePatchInstallEntry[]>(`/device/${device_id}/software-patch-installs`, params);
        if (!patches.length) return textResult(`No software patch install history for device ${device_id} matching filters.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: patches.length, patches });

        const lines = [`# Software Patch Install History — Device ${device_id} (${patches.length})`, ""];
        for (const p of patches) {
          lines.push(`- **${p.name ?? p.productIdentifier ?? "Unknown"}** — ${p.status ?? "N/A"} — installed ${fmtDate(p.installedAt)}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
