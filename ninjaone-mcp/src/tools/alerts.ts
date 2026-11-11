import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, fmtTs, paginationNote, ResponseFormat } from "../services/response-utils.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../constants.js";
import type { Alert } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

export function registerAlertTools(server: McpServer): void {
  // ── List Alerts ────────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_alerts",
    {
      title: "List Alerts",
      description: `List active alerts (triggered conditions) across all devices, with optional filters.

Returns open alerts including severity, message, device ID, and trigger time. Can be scoped to a
subset of devices using NinjaOne's device filter syntax.

Args:
  - source_type (string, optional): Filter by alert source (e.g. 'CONDITION', 'POLICY')
  - device_filter (string, optional): NinjaOne device filter expression to scope devices, e.g. "organization = 5"
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - after (string, optional): Cursor for next page (last alert UID from previous response)
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')

Returns: Alert UID, message, severity, device ID, organization ID, and trigger timestamp.

Use ninjaone_reset_alert to clear an alert's underlying condition, or ninjaone_delete_alert to
remove the alert record outright. Both take the UID returned here.`,
      inputSchema: z.object({
        source_type: z.string().optional().describe("Filter by source type, e.g. 'CONDITION'"),
        device_filter: z.string().optional().describe("NinjaOne device filter expression, e.g. 'organization = 5'"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        after: z.string().optional().describe("Last alert UID from previous page for pagination"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ source_type, device_filter, page_size, after, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (source_type) params["sourceType"] = source_type;
        if (device_filter) params["df"] = device_filter;
        if (after) params["after"] = after;

        const alerts = await client.get<Alert[]>("/alerts", params);
        if (!alerts.length) return textResult("No active alerts found.");

        const hasMore = alerts.length === page_size;
        const lastUid = alerts[alerts.length - 1]?.uid;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: alerts.length, has_more: hasMore, last_uid: lastUid, alerts });
        }

        const lines = [`# Active Alerts (${alerts.length}${hasMore ? "+" : ""})`, ""];
        for (const a of alerts) {
          const sev = a.severity ?? "N/A";
          const sevIcon = sev === "CRITICAL" ? "🔴" : sev === "MAJOR" ? "🟠" : sev === "MINOR" ? "🟡" : "⚪";
          lines.push(`## ${sevIcon} ${a.message ?? a.subject ?? "(no message)"}`);
          lines.push(`- **UID**: \`${a.uid}\``);
          lines.push(`- **Severity**: ${sev}`);
          lines.push(`- **Device ID**: ${a.deviceId ?? "N/A"}`);
          lines.push(`- **Organization ID**: ${a.organizationId ?? "N/A"}`);
          lines.push(`- **Triggered**: ${fmtTs(a.triggeredAt)}`);
          lines.push(`- **Type**: ${a.type ?? "N/A"}`);
          lines.push("");
        }
        lines.push(paginationNote(hasMore, lastUid));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Reset Alert (clear condition) ─────────────────────────────────────────

  server.registerTool(
    "ninjaone_reset_alert",
    {
      title: "Reset Alert",
      description: `Reset the monitoring condition behind an alert, by its UID.

This is the normal way to clear an alert once you've resolved the underlying issue — NinjaOne
re-evaluates the condition and the alert disappears if it no longer applies. Prefer this over
ninjaone_delete_alert, which only removes the alert record without touching the condition.

Args:
  - alert_uid (string): The alert UID (from ninjaone_list_alerts or ninjaone_get_device_alerts)`,
      inputSchema: z.object({
        alert_uid: z.string().uuid().describe("The alert UID to reset"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ alert_uid }) => {
      try {
        const client = getClient();
        await client.post(`/alert/${alert_uid}/reset`);
        return textResult(`✅ Alert \`${alert_uid}\` condition has been reset.`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Delete Alert ───────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_delete_alert",
    {
      title: "Delete Alert Record",
      description: `Permanently delete an alert record by its UID, without resetting its condition.

If the underlying issue is still active, NinjaOne may re-trigger a new alert later. To actually
clear the condition, use ninjaone_reset_alert instead.

Args:
  - alert_uid (string): The alert UID to delete`,
      inputSchema: z.object({
        alert_uid: z.string().uuid().describe("The alert UID to delete"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async ({ alert_uid }) => {
      try {
        const client = getClient();
        await client.delete(`/alert/${alert_uid}`);
        return textResult(`✅ Alert \`${alert_uid}\` record deleted.`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Reset All Alerts On A Device ───────────────────────────────────────────

  server.registerTool(
    "ninjaone_reset_device_alerts",
    {
      title: "Reset All Alerts On A Device",
      description: `Reset every active alert condition on a specific device.

NinjaOne has no single bulk endpoint for this, so it's implemented here as a workflow: fetch the
device's current alerts, then reset each one's condition. Returns a per-alert result so you can
see if any individual reset failed.

Args:
  - device_id (number): The device whose alerts should be cleared`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id }) => {
      try {
        const client = getClient();
        const alerts = await client.get<Alert[]>(`/device/${device_id}/alerts`);
        if (!alerts.length) return textResult(`Device ${device_id} has no active alerts to reset.`);

        const results: string[] = [];
        for (const a of alerts) {
          try {
            await client.post(`/alert/${a.uid}/reset`);
            results.push(`✅ \`${a.uid}\` — ${a.message ?? a.subject ?? "(no message)"}`);
          } catch (err) {
            results.push(`❌ \`${a.uid}\` — ${handleApiError(err)}`);
          }
        }
        return textResult(`# Reset ${alerts.length} alert(s) on device ${device_id}\n\n${results.join("\n")}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
