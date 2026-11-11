import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, ResponseFormat } from "../services/response-utils.js";
import type { Policy, NodeRole } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

const NODE_CLASSES = [
  "WINDOWS_SERVER",
  "WINDOWS_WORKSTATION",
  "LINUX_WORKSTATION",
  "MAC",
  "ANDROID",
  "VMWARE_VM_HOST",
  "VMWARE_VM_GUEST",
  "HYPERV_VMM_HOST",
  "HYPERV_VMM_GUEST",
  "LINUX_SERVER",
  "MAC_SERVER",
  "CLOUD_MONITOR_TARGET",
  "NMS_SWITCH",
  "NMS_ROUTER",
  "NMS_FIREWALL",
  "NMS_PRIVATE_NETWORK_GATEWAY",
  "NMS_PRINTER",
  "NMS_SCANNER",
  "NMS_DIAL_MANAGER",
  "NMS_WAP",
  "NMS_IPSLA",
  "NMS_COMPUTER",
  "NMS_VM_HOST",
  "NMS_APPLIANCE",
  "NMS_OTHER",
  "NMS_SERVER",
  "NMS_PHONE",
  "NMS_VIRTUAL_MACHINE",
  "NMS_NETWORK_MANAGEMENT_AGENT",
] as const;

export function registerPolicyTools(server: McpServer): void {
  // ── List Policies ──────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_policies",
    {
      title: "List Policies",
      description: `List all monitoring/management policies defined in NinjaOne.

Policies bundle monitoring thresholds, patch settings, and other configuration for a device
class; they're assigned to devices via node roles (see ninjaone_list_roles) or organization
mappings (see ninjaone_set_organization_policy_mappings).

Args:
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ response_format }) => {
      try {
        const client = getClient();
        const policies = await client.get<Policy[]>("/policies");
        if (!policies.length) return textResult("No policies found.");
        if (response_format === ResponseFormat.JSON) return jsonResult({ count: policies.length, policies });

        const lines = [`# Policies (${policies.length})`, ""];
        for (const p of policies) {
          lines.push(`- **${p.name ?? "(unnamed)"}** (ID: ${p.id}) — ${p.nodeClass ?? "N/A"}${p.enabled === false ? " — disabled" : ""}${p.parentPolicyId ? ` — inherits from ${p.parentPolicyId}` : ""}`);
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Create Policy ──────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_create_policy",
    {
      title: "Create Policy",
      description: `Create a new policy, optionally as a child of or copy of an existing one.

Args:
  - name (string): Policy name
  - node_class (string): Device class this policy applies to (e.g. 'WINDOWS_SERVER', 'WINDOWS_WORKSTATION', 'MAC', 'LINUX_SERVER')
  - description (string, optional): Policy description
  - mode (string, optional): 'NEW' (default, standalone policy), 'CHILD' (inherits from template_policy_id), or 'COPY' (clones template_policy_id)
  - template_policy_id (number, optional): Required when mode is 'CHILD' or 'COPY'
  - enabled (boolean, optional): Whether the policy is active (default: true)

Note: this creates the policy shell — configuring its actual monitoring/patch rules isn't exposed
by NinjaOne's public API and has to be done in the NinjaOne console.`,
      inputSchema: z.object({
        name: z.string().min(1).max(200).describe("Policy name"),
        node_class: z.enum(NODE_CLASSES).describe("Device class this policy applies to"),
        description: z.string().optional().describe("Policy description"),
        mode: z.enum(["NEW", "CHILD", "COPY"]).default("NEW").describe("Creation mode"),
        template_policy_id: z.number().int().optional().describe("Required when mode is CHILD or COPY"),
        enabled: z.boolean().default(true).describe("Whether the policy is active"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ name, node_class, description, mode, template_policy_id, enabled }) => {
      if ((mode === "CHILD" || mode === "COPY") && template_policy_id === undefined) {
        return textResult(`Error: template_policy_id is required when mode='${mode}'.`);
      }
      try {
        const client = getClient();
        const body: Record<string, unknown> = { name, nodeClass: node_class, enabled };
        if (description) body["description"] = description;
        if (template_policy_id !== undefined) body["parentPolicyId"] = template_policy_id;

        const params: Record<string, unknown> = { mode };
        if (template_policy_id !== undefined) params["templatePolicyId"] = template_policy_id;

        const policy = await client.post<Policy>("/policies", body, params);
        return textResult(`✅ Policy "${name}" created (ID: ${policy.id ?? "?"}, class: ${node_class}).`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Node Roles ─────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_roles",
    {
      title: "List Device Roles",
      description: `List device (node) roles. An organization's policy mapping assigns a policy to each
role, which is how devices in that org end up with a given policy for their class — you need a
role's ID for ninjaone_set_organization_policy_mappings.

Args:
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ response_format }) => {
      try {
        const client = getClient();
        const roles = await client.get<NodeRole[]>("/roles");
        if (!roles.length) return textResult("No node roles found.");
        if (response_format === ResponseFormat.JSON) return jsonResult({ count: roles.length, roles });

        const lines = [`# Device Roles (${roles.length})`, ""];
        for (const r of roles) lines.push(`- **${r.name ?? "(unnamed)"}** (ID: ${r.id}) — ${r.nodeClass ?? "N/A"}`);
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Set Organization Policy Mappings ────────────────────────────────────────

  server.registerTool(
    "ninjaone_set_organization_policy_mappings",
    {
      title: "Set Organization Policy Mappings",
      description: `Replace an organization's node-role → policy assignments — this is how you control which
policy applies to which class of device within that organization.

⚠️ This REPLACES the full mapping set for the organization, not a merge — include every
role/policy pair that should remain, not just the one you're changing. Use ninjaone_list_roles
and ninjaone_list_policies first to get valid IDs.

Args:
  - organization_id (number): The organization ID
  - mappings (array): List of {node_role_id, policy_id} pairs to set`,
      inputSchema: z.object({
        organization_id: z.number().int().describe("The organization ID"),
        mappings: z
          .array(
            z.object({
              node_role_id: z.number().int().describe("Node role ID, from ninjaone_list_roles"),
              policy_id: z.number().int().describe("Policy ID, from ninjaone_list_policies"),
            })
          )
          .min(1)
          .describe("Full replacement list of role -> policy mappings for this organization"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async ({ organization_id, mappings }) => {
      try {
        const client = getClient();
        const body = mappings.map((m) => ({ nodeRoleId: m.node_role_id, policyId: m.policy_id }));
        await client.put(`/organization/${organization_id}/policies`, body);
        return textResult(
          `✅ Organization ${organization_id} policy mappings set (${mappings.length} role/policy pair(s)):\n` +
            mappings.map((m) => `  - role ${m.node_role_id} → policy ${m.policy_id}`).join("\n")
        );
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
