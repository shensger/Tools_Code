import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, fmtTs, paginationNote, ResponseFormat } from "../services/response-utils.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../constants.js";
import type { Device, DeviceActivity } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

function deviceSummaryLines(d: Device): string[] {
  const lines = [`## ${d.displayName ?? d.systemName ?? `Device #${d.id}`} (ID: ${d.id})`];
  lines.push(`- **Status**: ${d.offline ? "🔴 Offline" : "🟢 Online"}`);
  lines.push(`- **OS**: ${d.os?.name ?? "Unknown"}`);
  lines.push(`- **Class**: ${d.nodeClass}`);
  lines.push(`- **Organization ID**: ${d.organizationId}`);
  if (d.ipAddresses?.length) lines.push(`- **IP**: ${d.ipAddresses.join(", ")}`);
  lines.push(`- **Last Contact**: ${fmtTs(d.lastContact ? Number(d.lastContact) : undefined)}`);
  return lines;
}

export function registerDeviceTools(server: McpServer): void {
  // ── List Devices ───────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_devices",
    {
      title: "List Devices",
      description: `List devices managed in NinjaOne with optional filters.

Returns a paginated list of devices. Use filters to narrow results by organization, class, OS, or policy.

Args:
  - organization_id (number, optional): Filter by organization ID
  - device_filter (string, optional): NinjaOne filter expression (e.g. "class = WINDOWS_SERVER")
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - after (number, optional): Cursor for next page (last device ID from previous response)
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')

Returns device id, name, OS, online status, organization, IP addresses, and last contact time.
For richer per-device data (OS build, network interfaces, hardware) in one call, use
ninjaone_list_devices_detailed instead. To search by name/user/IP substring, use
ninjaone_search_devices.

Examples:
  - List all devices: no filters
  - List Windows servers: device_filter="class = WINDOWS_SERVER"
  - List offline devices: device_filter="offline = true"`,
      inputSchema: z.object({
        organization_id: z.number().int().optional().describe("Filter by organization ID"),
        device_filter: z.string().optional().describe("NinjaOne device filter expression"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        after: z.number().int().optional().describe("Last device ID from previous page for pagination"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ organization_id, device_filter, page_size, after, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (after !== undefined) params["after"] = after;
        if (device_filter) params["df"] = device_filter;

        const path = organization_id ? `/organization/${organization_id}/devices` : "/devices";

        const devices = await client.get<Device[]>(path, params);

        if (!devices.length) return textResult("No devices found matching the given filters.");

        const hasMore = devices.length === page_size;
        const lastId = devices[devices.length - 1]?.id;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: devices.length, has_more: hasMore, last_id: lastId, devices });
        }

        const lines = [`# Devices (${devices.length}${hasMore ? "+" : ""})`, ""];
        for (const d of devices) {
          lines.push(...deviceSummaryLines(d), "");
        }
        lines.push(paginationNote(hasMore, lastId));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Devices Detailed ──────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_devices_detailed",
    {
      title: "List Devices (Detailed)",
      description: `List devices with the same filters as ninjaone_list_devices, but with richer per-device
data included in a single call (full OS info, hardware summary, network interfaces).

Prefer ninjaone_list_devices for a quick overview across many devices — this one is heavier per
device, so keep page_size modest when scanning a large fleet.

Args:
  - organization_id (number, optional): Filter by organization ID
  - device_filter (string, optional): NinjaOne filter expression (e.g. "class = WINDOWS_SERVER")
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - after (number, optional): Cursor for next page (last device ID from previous response)
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        organization_id: z.number().int().optional().describe("Filter by organization ID (applied client-side via device_filter)"),
        device_filter: z.string().optional().describe("NinjaOne device filter expression"),
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        after: z.number().int().optional().describe("Last device ID from previous page for pagination"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ organization_id, device_filter, page_size, after, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (after !== undefined) params["after"] = after;
        const filters = [device_filter, organization_id !== undefined ? `organization = ${organization_id}` : undefined].filter(Boolean);
        if (filters.length) params["df"] = filters.join(" AND ");

        const devices = await client.get<Device[]>("/devices-detailed", params);
        if (!devices.length) return textResult("No devices found matching the given filters.");

        const hasMore = devices.length === page_size;
        const lastId = devices[devices.length - 1]?.id;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: devices.length, has_more: hasMore, last_id: lastId, devices });
        }

        const lines = [`# Devices — Detailed (${devices.length}${hasMore ? "+" : ""})`, ""];
        for (const d of devices) {
          lines.push(...deviceSummaryLines(d));
          lines.push(`- **DNS/NetBIOS**: ${d.dnsName ?? "N/A"} / ${d.netbiosName ?? "N/A"}`);
          lines.push(`- **Model**: ${d.system?.manufacturer ?? ""} ${d.system?.model ?? ""}`.trim());
          lines.push("");
        }
        lines.push(paginationNote(hasMore, lastId));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Search Devices ─────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_search_devices",
    {
      title: "Search Devices",
      description: `Free-text search for devices by name, logged-on user, IP address, or similar identifying text.

Faster than building a device_filter expression when you just have a loose search term, e.g. a
hostname fragment or a person's username.

Args:
  - query (string): Search text (device name, user name, IP address, etc.)
  - limit (number, optional): Max devices to return (default: ${DEFAULT_PAGE_SIZE})
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        query: z.string().min(1).describe("Search text — device name, user name, IP, etc."),
        limit: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Max devices to return"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ query, limit, response_format }) => {
      try {
        const client = getClient();
        const devices = await client.get<Device[]>("/devices/search", { q: query, limit });
        if (!devices.length) return textResult(`No devices found matching "${query}".`);

        if (response_format === ResponseFormat.JSON) return jsonResult({ query, count: devices.length, devices });

        const lines = [`# Search Results for "${query}" (${devices.length})`, ""];
        for (const d of devices) lines.push(...deviceSummaryLines(d), "");
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Get Device ────────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device",
    {
      title: "Get Device Details",
      description: `Get full details for a specific device by ID.

Returns comprehensive information including OS, hardware, network interfaces, policy, and custom fields.

Args:
  - device_id (number): The device ID
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, response_format }) => {
      try {
        const client = getClient();
        const d = await client.get<Device>(`/device/${device_id}`);

        if (response_format === ResponseFormat.JSON) return jsonResult(d);

        const lines = [
          `# Device: ${d.displayName ?? d.systemName ?? `#${d.id}`}`,
          "",
          `- **ID**: ${d.id}`,
          `- **Status**: ${d.offline ? "🔴 Offline" : "🟢 Online"}`,
          `- **Class**: ${d.nodeClass}`,
          `- **Organization ID**: ${d.organizationId}`,
          `- **Location ID**: ${d.locationId ?? "N/A"}`,
          `- **Policy ID**: ${d.policyId ?? "N/A"}`,
          `- **Approval Status**: ${d.approvalStatus ?? "N/A"}`,
          `- **DNS Name**: ${d.dnsName ?? "N/A"}`,
          `- **NetBIOS Name**: ${d.netbiosName ?? "N/A"}`,
          `- **IP Addresses**: ${d.ipAddresses?.join(", ") ?? "N/A"}`,
          `- **Public IP**: ${d.publicIp ?? "N/A"}`,
          `- **Last Contact**: ${fmtTs(d.lastContact ? Number(d.lastContact) : undefined)}`,
          `- **Created**: ${fmtTs(d.created ? Number(d.created) : undefined)}`,
          "",
          "## OS",
          `- **Name**: ${d.os?.name ?? "N/A"}`,
          `- **Manufacturer**: ${d.os?.manufacturer ?? "N/A"}`,
          `- **Architecture**: ${d.os?.architecture ?? "N/A"}`,
          `- **Build**: ${d.os?.buildNumber ?? "N/A"}`,
          `- **Needs Reboot**: ${d.os?.needsReboot ?? false}`,
          "",
          "## Hardware",
          `- **Model**: ${d.system?.model ?? "N/A"}`,
          `- **Manufacturer**: ${d.system?.manufacturer ?? "N/A"}`,
          `- **Serial Number**: ${d.system?.serialNumber ?? "N/A"}`,
        ];
        if (d.tags?.length) lines.push("", `**Tags**: ${d.tags.join(", ")}`);
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Get Device Alerts ─────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device_alerts",
    {
      title: "Get Device Alerts",
      description: `Get active alerts for a specific device.

Returns all open alerts/conditions on the device including severity, message, and trigger time.

Args:
  - device_id (number): The device ID
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, response_format }) => {
      try {
        const client = getClient();
        const alerts = await client.get<Array<Record<string, unknown>>>(`/device/${device_id}/alerts`);

        if (!alerts.length) return textResult(`No active alerts for device ${device_id}.`);

        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: alerts.length, alerts });

        const lines = [`# Alerts for Device ${device_id} (${alerts.length})`, ""];
        for (const a of alerts) {
          const uid = String(a["uid"] ?? "");
          const msg = String(a["message"] ?? a["subject"] ?? "(no message)");
          const severity = String(a["severity"] ?? "N/A");
          const triggered = a["triggeredAt"] ? fmtTs(Number(a["triggeredAt"])) : "N/A";
          lines.push(`## ${msg}`);
          lines.push(`- **UID**: \`${uid}\``);
          lines.push(`- **Severity**: ${severity}`);
          lines.push(`- **Triggered**: ${triggered}`);
          lines.push(`- **Type**: ${String(a["type"] ?? "N/A")}`);
          lines.push("");
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Get Device Activities ─────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device_activities",
    {
      title: "Get Device Activity Log",
      description: `Get the activity log for a specific device.

Returns recent activities including script runs, patch installs, reboots, and alert events.

Args:
  - device_id (number): The device ID
  - page_size (number, optional): Results per page (default: ${DEFAULT_PAGE_SIZE})
  - older_than (number, optional): Activity ID to paginate backwards from
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        page_size: z.number().int().min(1).max(200).default(DEFAULT_PAGE_SIZE).describe("Number of activities to return"),
        older_than: z.number().int().optional().describe("Return activities older than this activity ID"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, page_size, older_than, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (older_than !== undefined) params["olderThan"] = older_than;

        const activities = await client.get<DeviceActivity[]>(`/device/${device_id}/activities`, params);

        if (!activities.length) return textResult(`No activities found for device ${device_id}.`);

        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: activities.length, activities });

        const lines = [`# Activity Log for Device ${device_id} (${activities.length})`, ""];
        for (const act of activities) {
          const when = act.created ? fmtTs(act.created) : "N/A";
          lines.push(`### [${when}] ${act.type ?? "Activity"} — ${act.status ?? ""}`);
          if (act.message) lines.push(act.message);
          if (act.userName) lines.push(`_by ${act.userName}_`);
          lines.push("");
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Get Device Jobs ────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device_jobs",
    {
      title: "Get Device Jobs",
      description: `List currently active jobs on a specific device — script runs, patch installs, and other
queued actions, with their status.

Use this right after ninjaone_run_script_or_action to watch a script's progress, or to see what
NinjaOne is currently doing to a device.

Args:
  - device_id (number): The device ID
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, response_format }) => {
      try {
        const client = getClient();
        const jobs = await client.get<Array<Record<string, unknown>>>(`/device/${device_id}/jobs`);
        if (!jobs.length) return textResult(`No active jobs on device ${device_id}.`);

        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: jobs.length, jobs });

        const lines = [`# Active Jobs — Device ${device_id} (${jobs.length})`, ""];
        for (const j of jobs) {
          lines.push(`- ${String(j["jobType"] ?? j["type"] ?? "job")} — ${String(j["status"] ?? "UNKNOWN")}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Reboot Device ─────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_reboot_device",
    {
      title: "Reboot Device",
      description: `Schedule a reboot for a device.

Queues a reboot command for the specified device. The device must be online and managed by NinjaOne.

Args:
  - device_id (number): The device ID to reboot
  - mode (string, optional): Reboot mode — 'NORMAL' (default, waits for a graceful shutdown) or
    'FORCED' (kills processes immediately)
  - reason (string, optional): Reason for the reboot (logged in activity)

⚠️ This is a destructive action that will interrupt active sessions.`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID to reboot"),
        mode: z.enum(["NORMAL", "FORCED"]).default("NORMAL").describe("Reboot mode"),
        reason: z.string().optional().describe("Reason for the reboot"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ device_id, mode, reason }) => {
      try {
        const client = getClient();
        const body: Record<string, unknown> = {};
        if (reason) body["reason"] = reason;

        await client.post(`/device/${device_id}/reboot/${mode}`, body);
        return textResult(`✅ Reboot (${mode}) scheduled for device ${device_id}.${reason ? ` Reason: "${reason}"` : ""}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Approve / Reject Devices ───────────────────────────────────────────────

  server.registerTool(
    "ninjaone_approve_devices",
    {
      title: "Approve Or Reject Pending Devices",
      description: `Approve or reject one or more devices that are pending approval (organizations with manual
approval mode queue newly-discovered devices here).

Args:
  - mode (string): 'APPROVE' or 'REJECT'
  - device_ids (array of numbers): Device IDs to approve/reject (max 200 per call)

⚠️ Rejecting a device removes it from management.`,
      inputSchema: z.object({
        mode: z.enum(["APPROVE", "REJECT"]).describe("Approval action to perform"),
        device_ids: z.array(z.number().int()).min(1).max(200).describe("Device IDs to approve/reject"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async ({ mode, device_ids }) => {
      try {
        const client = getClient();
        await client.post(`/devices/approval/${mode}`, { devices: device_ids });
        return textResult(`✅ ${mode === "APPROVE" ? "Approved" : "Rejected"} ${device_ids.length} device(s): ${device_ids.join(", ")}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
