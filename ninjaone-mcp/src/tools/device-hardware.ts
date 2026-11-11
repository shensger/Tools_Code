import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, fmtDate, ResponseFormat } from "../services/response-utils.js";
import type { WindowsService, DiskDrive, Volume, Processor, SoftwareEntry } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

export function registerDeviceHardwareTools(server: McpServer): void {
  // ── Get Device Windows Services ───────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device_services",
    {
      title: "Get Device Windows Services",
      description: `Get the list of Windows services running on a device.

Only works for Windows devices. Returns service name, display name, state, and start type.

Args:
  - device_id (number): The device ID (must be a Windows device)
  - name (string, optional): Filter services by name (partial match)
  - state (string, optional): Filter by state (e.g. 'RUNNING', 'STOPPED')
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')

Use ninjaone_control_windows_service to start/stop/restart a service found here.`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The Windows device ID"),
        name: z.string().optional().describe("Filter services by name (partial match)"),
        state: z.string().optional().describe("Filter by state, e.g. 'RUNNING' or 'STOPPED'"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, name, state, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = {};
        if (name) params["name"] = name;
        if (state) params["state"] = state;

        const services = await client.get<WindowsService[]>(`/device/${device_id}/windows-services`, params);

        if (!services.length) return textResult(`No services found on device ${device_id} matching filters.`);

        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: services.length, services });

        const lines = [`# Windows Services on Device ${device_id} (${services.length})`, ""];
        for (const svc of services) {
          const stateIcon = svc.state === "RUNNING" ? "🟢" : "🔴";
          lines.push(`- ${stateIcon} **${svc.displayName ?? svc.name}** (\`${svc.name}\`)`);
          lines.push(`  - State: ${svc.state ?? "N/A"} | Start: ${svc.startType ?? "N/A"} | Log on as: ${svc.logOnAs ?? "N/A"}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Control Windows Service ────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_control_windows_service",
    {
      title: "Start/Stop/Restart Windows Service",
      description: `Start, stop, or restart a Windows service on a device.

Get the exact service name with ninjaone_get_device_services first (use the short service name,
not the display name).

Args:
  - device_id (number): The Windows device ID
  - service_name (string): The service's short name (e.g. "Spooler", not "Print Spooler")
  - action (string): 'START', 'STOP', 'PAUSE', or 'RESTART'

⚠️ Stopping a service the device depends on can disrupt it. Confirm the service name is correct.`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The Windows device ID"),
        service_name: z.string().min(1).describe("Service short name, e.g. 'Spooler'"),
        action: z.enum(["START", "STOP", "PAUSE", "RESTART"]).describe("Action to perform on the service"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ device_id, service_name, action }) => {
      try {
        const client = getClient();
        await client.post(`/device/${device_id}/windows-service/${encodeURIComponent(service_name)}/control`, { action });
        return textResult(`✅ Sent ${action} to service "${service_name}" on device ${device_id}.`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Device Disks ──────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_device_disks",
    {
      title: "List Device Disk Drives",
      description: `List the physical disk drives on a device (model, manufacturer, capacity, interface).

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
        const disks = await client.get<DiskDrive[]>(`/device/${device_id}/disks`);
        if (!disks.length) return textResult(`No disk drives reported for device ${device_id}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: disks.length, disks });

        const lines = [`# Disk Drives — Device ${device_id} (${disks.length})`, ""];
        for (const d of disks) {
          const capacityGb = d.capacity ? (d.capacity / 1e9).toFixed(1) + " GB" : "N/A";
          lines.push(`- **${d.model ?? d.name ?? "Unknown drive"}** (${d.manufacturer ?? "N/A"}) — ${capacityGb} — ${d.interfaceType ?? "N/A"}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Device Volumes ─────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_device_volumes",
    {
      title: "List Device Storage Volumes",
      description: `List storage volumes on a device — drive letters/labels, filesystem, capacity, and free space.
Handy for spotting low disk space.

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
        const volumes = await client.get<Volume[]>(`/device/${device_id}/volumes`);
        if (!volumes.length) return textResult(`No volumes reported for device ${device_id}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: volumes.length, volumes });

        const lines = [`# Storage Volumes — Device ${device_id} (${volumes.length})`, ""];
        for (const v of volumes) {
          const cap = v.capacity ? (v.capacity / 1e9).toFixed(1) : "?";
          const free = v.freeSpace ? (v.freeSpace / 1e9).toFixed(1) : "?";
          const pctFree = v.capacity && v.freeSpace ? Math.round((v.freeSpace / v.capacity) * 100) : null;
          const warn = pctFree !== null && pctFree < 15 ? " ⚠️ low free space" : "";
          lines.push(`- **${v.label ?? v.name ?? v.deviceName ?? "Volume"}** (${v.fileSystem ?? "N/A"}) — ${free}/${cap} GB free${pctFree !== null ? ` (${pctFree}%)` : ""}${warn}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Device Processors ─────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_device_processors",
    {
      title: "List Device Processors",
      description: `List the CPU(s) installed on a device.

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
        const procs = await client.get<Processor[]>(`/device/${device_id}/processors`);
        if (!procs.length) return textResult(`No processors reported for device ${device_id}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: procs.length, processors: procs });

        const lines = [`# Processors — Device ${device_id} (${procs.length})`, ""];
        for (const p of procs) {
          lines.push(`- **${p.name ?? "Unknown CPU"}** (${p.manufacturer ?? "N/A"}) — ${p.numCores ?? "?"} cores / ${p.numLogicalProcessors ?? "?"} logical`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Device Software ───────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_device_software",
    {
      title: "List Software Installed On A Device",
      description: `List all software installed on one specific device.

For a fleet-wide software search across many devices, use ninjaone_query_software instead.

Args:
  - device_id (number): The device ID
  - name (string, optional): Filter results to names containing this text (applied client-side)
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        name: z.string().optional().describe("Filter to software names containing this text"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, name, response_format }) => {
      try {
        const client = getClient();
        let software = await client.get<SoftwareEntry[]>(`/device/${device_id}/software`);
        if (name) {
          const needle = name.toLowerCase();
          software = software.filter((s) => (s.name ?? "").toLowerCase().includes(needle));
        }
        if (!software.length) return textResult(`No software found on device ${device_id}${name ? ` matching "${name}"` : ""}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, count: software.length, software });

        const lines = [`# Software — Device ${device_id} (${software.length})`, ""];
        for (const s of software) {
          lines.push(`- **${s.name ?? "Unknown"}** v${s.version ?? "?"} — ${s.publisher ?? "N/A"} — installed ${fmtDate(s.installDate)}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Get Last Logged On User ────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_last_logged_on_user",
    {
      title: "Get Last Logged-On User",
      description: `Get the username of the last person logged into a device.

Args:
  - device_id (number): The device ID`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id }) => {
      try {
        const client = getClient();
        const result = await client.get<{ userName?: string } | string>(`/device/${device_id}/last-logged-on-user`);
        const userName = typeof result === "string" ? result : result.userName;
        return textResult(userName ? `Last logged-on user for device ${device_id}: **${userName}**` : `No logged-on user recorded for device ${device_id}.`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
