import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, fmtTs, ResponseFormat } from "../services/response-utils.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

export function registerDeviceConfigTools(server: McpServer): void {
  // ── Get Device Custom Fields ───────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device_custom_fields",
    {
      title: "Get Device Custom Fields",
      description: `Get the current values of all custom fields defined on a device.

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
        const fields = await client.get<Record<string, unknown>>(`/device/${device_id}/custom-fields`);
        const entries = Object.entries(fields ?? {});
        if (!entries.length) return textResult(`No custom fields set on device ${device_id}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, fields });

        const lines = [`# Custom Fields — Device ${device_id}`, ""];
        for (const [k, v] of entries) lines.push(`- **${k}**: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Update Device Custom Fields ────────────────────────────────────────────

  server.registerTool(
    "ninjaone_update_device_custom_fields",
    {
      title: "Update Device Custom Fields",
      description: `Set one or more custom field values on a device.

Args:
  - device_id (number): The device ID
  - fields (object): Map of field name -> new value. Only the fields you include are changed.

Example: fields={"assetTag": "IT-0042", "warrantyExpiry": "2027-01-01"}`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        fields: z.record(z.unknown()).refine((f) => Object.keys(f).length > 0, "fields must not be empty").describe("Map of field name to new value"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, fields }) => {
      try {
        const client = getClient();
        await client.patch(`/device/${device_id}/custom-fields`, fields);
        return textResult(`✅ Updated custom field(s) on device ${device_id}: ${Object.keys(fields).join(", ")}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Set Device Maintenance ─────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_set_device_maintenance",
    {
      title: "Schedule Device Maintenance Window",
      description: `Put a device into maintenance mode for a time window, which suppresses its alerts during
that window — useful before planned work so routine changes don't fire alerts.

Args:
  - device_id (number): The device ID
  - start_epoch_seconds (number): Window start, Unix epoch seconds
  - end_epoch_seconds (number): Window end, Unix epoch seconds

Use ninjaone_clear_device_maintenance to end it early.`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
        start_epoch_seconds: z.number().describe("Maintenance window start, Unix epoch seconds"),
        end_epoch_seconds: z.number().describe("Maintenance window end, Unix epoch seconds"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id, start_epoch_seconds, end_epoch_seconds }) => {
      if (end_epoch_seconds <= start_epoch_seconds) {
        return textResult("Error: end_epoch_seconds must be after start_epoch_seconds.");
      }
      try {
        const client = getClient();
        await client.put(`/device/${device_id}/maintenance`, { start: start_epoch_seconds, end: end_epoch_seconds });
        return textResult(
          `✅ Maintenance window set on device ${device_id}: ${fmtTs(start_epoch_seconds)} → ${fmtTs(end_epoch_seconds)}`
        );
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Clear Device Maintenance ────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_clear_device_maintenance",
    {
      title: "End Device Maintenance Window",
      description: `Cancel/end a device's maintenance mode immediately.

Args:
  - device_id (number): The device ID`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id }) => {
      try {
        const client = getClient();
        await client.delete(`/device/${device_id}/maintenance`);
        return textResult(`✅ Maintenance mode ended for device ${device_id}.`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Get Device Policy Overrides ─────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_device_policy_overrides",
    {
      title: "Get Device Policy Overrides",
      description: `Get a summary of any monitoring/policy settings overridden on this specific device,
away from what its assigned policy would otherwise apply.

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
        const overrides = await client.get<unknown>(`/device/${device_id}/policy/overrides`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ device_id, overrides });
        return textResult(`# Policy Overrides — Device ${device_id}\n\n\`\`\`json\n${JSON.stringify(overrides, null, 2)}\n\`\`\``);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Clear Device Policy Overrides ───────────────────────────────────────────

  server.registerTool(
    "ninjaone_clear_device_policy_overrides",
    {
      title: "Clear Device Policy Overrides",
      description: `Reset a device back to fully inheriting its assigned policy, removing any device-level
overrides.

Args:
  - device_id (number): The device ID`,
      inputSchema: z.object({
        device_id: z.number().int().describe("The device ID"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async ({ device_id }) => {
      try {
        const client = getClient();
        await client.delete(`/device/${device_id}/policy/overrides`);
        return textResult(`✅ Policy overrides cleared on device ${device_id} — it now fully inherits its assigned policy.`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
