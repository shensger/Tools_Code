import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, fmtTs, ResponseFormat } from "../services/response-utils.js";
import { MAX_PAGE_SIZE } from "../constants.js";
import type { Alert, TicketSummary } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

interface TicketStatus {
  statusId?: number;
  id?: number;
  name?: string;
  displayName?: string;
  parentId?: number;
  [key: string]: unknown;
}

const SEVERITY_ORDER = ["CRITICAL", "MAJOR", "MODERATE", "MINOR", "NONE"];

function fmtValue(v: unknown): string {
  return typeof v === "object" && v !== null ? JSON.stringify(v) : String(v);
}

export function registerExtraTools(server: McpServer): void {
  // ── Get Ticket ──────────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_ticket",
    {
      title: "Get Ticket",
      description: `Get one NinjaOne ticket by ID (no board search needed): summary, status, type, severity,
priority, organization, device, assignee, requester, tags, attributes and timestamps.

Use ninjaone_get_ticket_log_entries for the comment history.

Args:
  - ticket_id (number): The ticket ID
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        ticket_id: z.number().int().describe("The ticket ID"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ ticket_id, response_format }) => {
      try {
        const t = await getClient().get<TicketSummary>(`/ticketing/ticket/${ticket_id}`);
        if (response_format === ResponseFormat.JSON) return jsonResult(t);

        const rawStatus = (t as Record<string, unknown>)["status"];
        const status = typeof rawStatus === "object" && rawStatus !== null
          ? ((rawStatus as Record<string, unknown>)["displayName"] ?? (rawStatus as Record<string, unknown>)["name"])
          : rawStatus;
        const lines = [
          `# Ticket #${t.id}: ${t.summary ?? "(no summary)"}`,
          "",
          `- **Status**: ${status ?? "N/A"}`,
          `- **Type**: ${t.type ?? "N/A"}`,
          `- **Severity / Priority**: ${t.severity ?? "N/A"} / ${t["priority"] ?? "N/A"}`,
          `- **Organization ID**: ${t.clientId ?? "N/A"}`,
          `- **Device ID**: ${t.nodeId ?? "N/A"}`,
          `- **Assigned app user ID**: ${t.assignedAppUserId ?? "unassigned"}`,
          `- **Requester**: ${fmtValue(t["requesterUid"] ?? "N/A")}`,
          `- **Board/Form**: ${fmtValue(t["ticketFormId"] ?? "N/A")}`,
          `- **Tags**: ${Array.isArray(t["tags"]) && (t["tags"] as unknown[]).length ? (t["tags"] as unknown[]).join(", ") : "none"}`,
          `- **Created**: ${fmtTs(t.createTime)}`,
          `- **Updated**: ${fmtTs(t.updateTime)}`,
        ];
        const attrs = t["attributeValues"];
        if (Array.isArray(attrs) && attrs.length) {
          lines.push("", "## Attributes");
          for (const a of attrs as Array<Record<string, unknown>>) lines.push(`- ${fmtValue(a["attributeId"])}: ${fmtValue(a["value"])}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Ticket Statuses ────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_ticket_statuses",
    {
      title: "List Ticket Statuses",
      description: `List the ticket statuses configured in this NinjaOne tenant (built-in NEW/OPEN/WAITING/PAUSED/
RESOLVED/CLOSED plus any custom statuses), with their IDs. Check this before ninjaone_update_ticket
so the status you set is valid.

Args:
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({ response_format: ResponseFormatSchema }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ response_format }) => {
      try {
        const statuses = await getClient().get<TicketStatus[]>("/ticketing/statuses");
        if (!statuses?.length) return textResult("No ticket statuses returned.");
        if (response_format === ResponseFormat.JSON) return jsonResult({ count: statuses.length, statuses });
        const lines = [`# Ticket Statuses (${statuses.length})`, ""];
        for (const s of statuses) {
          const id = s.statusId ?? s.id;
          const label = s.displayName && s.displayName !== s.name ? `${s.displayName} (\`${s.name}\`)` : `\`${s.name ?? "?"}\``;
          lines.push(`- ${label} — id ${id ?? "?"}${s.parentId !== undefined ? `, parent ${s.parentId}` : ""}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Organization Custom Fields ──────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_organization_custom_fields",
    {
      title: "Get Organization Custom Fields",
      description: `Get the current values of all organization-level custom fields for a NinjaOne organization
(client-wide values such as contract details, documentation links, or settings).

Args:
  - organization_id (number): The organization ID
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        organization_id: z.number().int().describe("The organization ID"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ organization_id, response_format }) => {
      try {
        const fields = await getClient().get<Record<string, unknown>>(`/organization/${organization_id}/custom-fields`);
        const entries = Object.entries(fields ?? {});
        if (!entries.length) return textResult(`No custom fields set on organization ${organization_id}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ organization_id, fields });
        const lines = [`# Custom Fields — Organization ${organization_id}`, ""];
        for (const [k, v] of entries) lines.push(`- **${k}**: ${fmtValue(v)}`);
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  server.registerTool(
    "ninjaone_update_organization_custom_fields",
    {
      title: "Update Organization Custom Fields",
      description: `Set one or more organization-level custom field values. Only the fields you include are changed.
Read the current values with ninjaone_get_organization_custom_fields first.

Args:
  - organization_id (number): The organization ID
  - fields (object): Map of field name -> new value

Example: fields={"contractRenewal": "2027-03-01", "primaryContact": "Jane Doe"}`,
      inputSchema: z.object({
        organization_id: z.number().int().describe("The organization ID"),
        fields: z.record(z.unknown()).describe("Map of custom field name to new value"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ organization_id, fields }) => {
      try {
        const names = Object.keys(fields ?? {});
        if (!names.length) return textResult("Error: provide at least one field to update.");
        await getClient().patch(`/organization/${organization_id}/custom-fields`, fields);
        return textResult(`✅ Updated ${names.length} custom field(s) on organization ${organization_id}: ${names.join(", ")}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Alert Summary ───────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_alert_summary",
    {
      title: "Alert Summary",
      description: `Count active alerts by severity, priority, organization and condition across the
tenant — a quick morning check without paging through every alert. Pages through /alerts
internally, up to max_alerts.

Args:
  - device_filter (string, optional): NinjaOne device filter to scope, e.g. "organization = 5"
  - max_alerts (number, optional): Stop after this many alerts (default 2000)
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_filter: z.string().optional().describe("NinjaOne device filter expression"),
        max_alerts: z.number().int().min(1).max(20000).default(2000).describe("Upper bound on alerts to scan"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device_filter, max_alerts, response_format }) => {
      try {
        const client = getClient();
        const all: Alert[] = [];
        let after: string | undefined;
        while (all.length < max_alerts) {
          const params: Record<string, unknown> = { pageSize: MAX_PAGE_SIZE };
          if (device_filter) params["df"] = device_filter;
          if (after) params["after"] = after;
          const page = await client.get<Alert[]>("/alerts", params);
          if (!page?.length) break;
          all.push(...page);
          if (page.length < MAX_PAGE_SIZE) break;
          const last = page[page.length - 1]?.uid;
          if (!last || last === after) break;
          after = last;
        }
        const truncated = all.length >= max_alerts;
        const alerts = all.slice(0, max_alerts);

        // Alerts carry deviceId but not organizationId: map devices -> orgs (best effort).
        const deviceOrg: Record<string, string> = {};
        const orgNames: Record<string, string> = {};
        try {
          let devAfter: number | undefined;
          for (let i = 0; i < 50; i++) {
            const params: Record<string, unknown> = { pageSize: 1000 };
            if (devAfter !== undefined) params["after"] = devAfter;
            const devs = await client.get<Array<{ id: number; organizationId?: number }>>("/devices", params);
            if (!devs?.length) break;
            for (const d of devs) deviceOrg[String(d.id)] = String(d.organizationId ?? "unknown");
            if (devs.length < 1000) break;
            devAfter = devs[devs.length - 1].id;
          }
          const orgs = await client.get<Array<{ id: number; name?: string }>>("/organizations", { pageSize: 1000 });
          for (const o of orgs ?? []) orgNames[String(o.id)] = o.name ?? String(o.id);
        } catch {
          /* org grouping is optional */
        }

        const bySeverity: Record<string, number> = {};
        const byPriority: Record<string, number> = {};
        const byOrg: Record<string, { total: number; critical: number; major: number }> = {};
        const byType: Record<string, number> = {};
        for (const a of alerts) {
          const raw = a as Alert & Record<string, unknown>;
          const sev = (a.severity ?? "NONE").toUpperCase();
          bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
          const pri = (a.priority ?? "NONE").toUpperCase();
          byPriority[pri] = (byPriority[pri] ?? 0) + 1;
          const org = String(a.organizationId ?? deviceOrg[String(a.deviceId)] ?? "unknown");
          byOrg[org] ??= { total: 0, critical: 0, major: 0 };
          byOrg[org].total++;
          if (sev === "CRITICAL" || pri === "HIGH") byOrg[org].critical++;
          if (sev === "MAJOR" || pri === "MEDIUM") byOrg[org].major++;
          const type = String(raw["conditionName"] || raw["sourceType"] || a.type || "unknown");
          byType[type] = (byType[type] ?? 0) + 1;
        }

        const summary = {
          total: alerts.length,
          truncated,
          by_severity: bySeverity,
          by_priority: byPriority,
          by_organization: Object.entries(byOrg)
            .map(([id, c]) => ({ organization_id: id, name: orgNames[id] ?? id, ...c }))
            .sort((x, y) => y.critical - x.critical || y.major - x.major || y.total - x.total),
          by_type: Object.entries(byType).sort((x, y) => y[1] - x[1]).map(([type, count]) => ({ type, count })),
        };
        if (response_format === ResponseFormat.JSON) return jsonResult(summary);

        const sevKeys = Object.keys(bySeverity).sort((x, y) => {
          const ix = SEVERITY_ORDER.indexOf(x), iy = SEVERITY_ORDER.indexOf(y);
          return (ix < 0 ? 99 : ix) - (iy < 0 ? 99 : iy);
        });
        const lines = [
          `# Alert Summary — ${alerts.length} active alert(s)${truncated ? ` (stopped at ${max_alerts})` : ""}${device_filter ? ` where ${device_filter}` : ""}`,
          "",
          "## By severity",
          ...sevKeys.map((k) => `- **${k}**: ${bySeverity[k]}`),
          "",
          "## By priority",
          ...Object.entries(byPriority).sort((x, y) => y[1] - x[1]).map(([k, v]) => `- **${k}**: ${v}`),
          "",
          "## By organization",
          "| Organization | Critical / high | Major / medium | Total |",
          "|---|---|---|---|",
          ...summary.by_organization.map((o) => `| ${o.name} (${o.organization_id}) | ${o.critical} | ${o.major} | ${o.total} |`),
          "",
          "## Top alert types",
          ...summary.by_type.slice(0, 10).map((t) => `- ${t.type}: ${t.count}`),
        ];
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
