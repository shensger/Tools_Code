import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, fmtTs, ResponseFormat } from "../services/response-utils.js";
import type { ScriptingOption, JobEntry } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

export function registerScriptTools(server: McpServer): void {
  // ── Get Device Scripting Options ──────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device_scripting_options",
    {
      title: "List Runnable Scripts & Actions For A Device",
      description: `List the scripts and built-in actions that can actually be run on a specific device.

NinjaOne doesn't expose a single global script library over the API — what's runnable depends on
the device's OS and the scripts assigned to it — so this is the one place to look up a valid
"id" (custom script) or "uid" (built-in action) before calling ninjaone_run_script_or_action.
Always call this first if you don't already know the script/action identifier for this device.

Args:
  - device_id (number): The device to list options for
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')

Returns each option's type (SCRIPT or ACTION), id/uid, name, and any variables it accepts.`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, response_format }) => {
      try {
        const client = getClient();
        const options = await client.get<ScriptingOption[]>(`/device/${device_id}/scripting/options`);

        if (!options.length) return textResult(`No runnable scripts or actions found for device ${device_id}.`);

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ device_id, count: options.length, options });
        }

        const lines = [`# Runnable Scripts & Actions — Device ${device_id} (${options.length})`, ""];
        for (const o of options) {
          const identifier = o.type === "ACTION" ? `uid: \`${o.uid}\`` : `id: \`${o.id}\``;
          lines.push(`## ${o.name ?? "(unnamed)"} — ${o.type ?? "?"}`);
          lines.push(`- **Identifier**: ${identifier}`);
          if (o.description) lines.push(`- **Description**: ${o.description}`);
          if (o.language) lines.push(`- **Language**: ${o.language}`);
          if (o.scriptVariables?.length) {
            const vars = o.scriptVariables.map((v) => `${v.name}${v.required ? "*" : ""}`).join(", ");
            lines.push(`- **Variables**: ${vars}`);
          }
          lines.push("");
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Run Script Or Action ──────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_run_script_or_action",
    {
      title: "Run Script Or Action On Device",
      description: `Execute a custom script or a built-in action on a target device.

Queues the run as a job on the device; check ninjaone_get_device_jobs or
ninjaone_list_active_jobs afterwards to see it progress, and ninjaone_get_device_activities
for the completed result and any output. Look up valid identifiers first with
ninjaone_get_device_scripting_options — NinjaOne rejects unknown ids/uids.

Args:
  - device_id (number): The target device ID
  - kind (string): 'SCRIPT' for a custom script (use script_id) or 'ACTION' for a built-in action (use action_uid)
  - script_id (number, optional): Required when kind='SCRIPT' — the script identifier
  - action_uid (string, optional): Required when kind='ACTION' — the built-in action's UUID
  - parameters (string, optional): Raw parameter string passed to the script/action, exactly as
    NinjaOne would pass command-line arguments (space-separated, quote as needed) — NOT a
    key-value map
  - run_as (string, optional): Credential role/identifier to run as (omit to use the device default)

⚠️ Scripts/actions can run with elevated privileges depending on the run-as context. Only run
scripts you trust, and double-check device_id before running anything destructive.`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The target device ID"),
        kind: z.enum(["SCRIPT", "ACTION"]).describe("SCRIPT for a custom script, ACTION for a built-in action"),
        script_id: z.number().int().optional().describe("Script identifier — required when kind='SCRIPT'"),
        action_uid: z.string().optional().describe("Built-in action UUID — required when kind='ACTION'"),
        parameters: z.string().optional().describe("Raw parameter string, e.g. \"-Force -Path C:\\\\temp\""),
        run_as: z.string().optional().describe("Credential role/identifier to run as"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ device_id, kind, script_id, action_uid, parameters, run_as }) => {
      if (kind === "SCRIPT" && script_id === undefined) {
        return textResult("Error: script_id is required when kind='SCRIPT'. Look one up with ninjaone_get_device_scripting_options.");
      }
      if (kind === "ACTION" && !action_uid) {
        return textResult("Error: action_uid is required when kind='ACTION'. Look one up with ninjaone_get_device_scripting_options.");
      }
      try {
        const client = getClient();
        const body: Record<string, unknown> = { type: kind };
        if (kind === "SCRIPT") body["id"] = script_id;
        if (kind === "ACTION") body["uid"] = action_uid;
        if (parameters) body["parameters"] = parameters;
        if (run_as) body["runAs"] = run_as;

        await client.post(`/device/${device_id}/script/run`, body);
        const label = kind === "SCRIPT" ? `script ${script_id}` : `action ${action_uid}`;
        return textResult(
          `✅ ${label} queued on device ${device_id}.\n\n` +
            `Check progress with ninjaone_get_device_jobs(device_id=${device_id}) or ` +
            `ninjaone_get_device_activities(device_id=${device_id}).`
        );
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Active Jobs (fleet-wide) ─────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_active_jobs",
    {
      title: "List Active Jobs (Fleet-Wide)",
      description: `List currently active/running jobs across all devices — script runs, patch installs, and
other queued actions.

Useful for checking on a script you just ran, or for spotting stuck/long-running jobs across the
fleet. Use ninjaone_get_device_jobs to scope this to one device instead.

Args:
  - job_type (string, optional): Filter by job type, e.g. 'SCRIPT', 'PATCH_INSTALL'
  - device_filter (string, optional): NinjaOne device filter expression to scope devices
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        job_type: z.string().optional().describe("Filter by job type, e.g. 'SCRIPT'"),
        device_filter: z.string().optional().describe("NinjaOne device filter expression"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ job_type, device_filter, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = {};
        if (job_type) params["jobType"] = job_type;
        if (device_filter) params["df"] = device_filter;

        const jobs = await client.get<JobEntry[]>("/jobs", params);
        if (!jobs.length) return textResult("No active jobs found.");

        if (response_format === ResponseFormat.JSON) return jsonResult({ count: jobs.length, jobs });

        const lines = [`# Active Jobs (${jobs.length})`, ""];
        for (const j of jobs) {
          lines.push(`- **Device ${j.deviceId ?? "?"}** — ${j.jobType ?? j.type ?? "job"} — ${j.status ?? "UNKNOWN"} (started ${fmtTs(j.startTime)})`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
