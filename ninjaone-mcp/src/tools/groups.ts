import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, ResponseFormat } from "../services/response-utils.js";
import type { DeviceGroup } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

export function registerGroupTools(server: McpServer): void {
  // ── List Groups ────────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_groups",
    {
      title: "List Device Groups",
      description: `List saved device groups (dashboard groups built from a device filter/query).

Args:
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')

Use ninjaone_list_group_device_ids to get the actual devices currently matching a group.`,
      inputSchema: z.object({
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ response_format }) => {
      try {
        const client = getClient();
        const groups = await client.get<DeviceGroup[]>("/groups");
        if (!groups.length) return textResult("No device groups found.");
        if (response_format === ResponseFormat.JSON) return jsonResult({ count: groups.length, groups });

        const lines = [`# Device Groups (${groups.length})`, ""];
        for (const g of groups) lines.push(`- **${g.name ?? "(unnamed)"}** (ID: ${g.id})`);
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Group Device IDs ──────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_group_device_ids",
    {
      title: "List Devices In A Group",
      description: `List the device IDs currently matching a saved device group.

Args:
  - group_id (number): The group ID (from ninjaone_list_groups)

Pass the returned IDs to ninjaone_get_device for details on each.`,
      inputSchema: z.object({
        group_id: z.number().int().describe("The group ID"),
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ group_id }) => {
      try {
        const client = getClient();
        const ids = await client.get<number[]>(`/group/${group_id}/device-ids`);
        if (!ids.length) return textResult(`Group ${group_id} currently matches no devices.`);
        return textResult(`# Devices in Group ${group_id} (${ids.length})\n\n${ids.join(", ")}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
