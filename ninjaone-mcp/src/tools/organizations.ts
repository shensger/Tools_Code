import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, paginationNote, ResponseFormat } from "../services/response-utils.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../constants.js";
import type { Organization, OrganizationLocation } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

export function registerOrganizationTools(server: McpServer): void {
  // ── List Organizations ─────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_organizations",
    {
      title: "List Organizations",
      description: `List all organizations (customers/clients) in NinjaOne.

Returns a paginated list of organizations with ID, name, and description.

Args:
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - after (number, optional): Last organization ID for pagination
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        after: z.number().int().optional().describe("Last organization ID from previous page"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ page_size, after, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (after !== undefined) params["after"] = after;

        const orgs = await client.get<Organization[]>("/organizations", params);
        if (!orgs.length) return textResult("No organizations found.");

        const hasMore = orgs.length === page_size;
        const lastId = orgs[orgs.length - 1]?.id;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: orgs.length, has_more: hasMore, last_id: lastId, organizations: orgs });
        }

        const lines = [`# Organizations (${orgs.length}${hasMore ? "+" : ""})`, ""];
        for (const org of orgs) {
          lines.push(`- **${org.name}** (ID: ${org.id})${org.description ? ` — ${org.description}` : ""}`);
        }
        lines.push(paginationNote(hasMore, lastId));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Organizations Detailed ────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_organizations_detailed",
    {
      title: "List Organizations (Detailed)",
      description: `Same as ninjaone_list_organizations, but with each organization's fuller payload
(tags, custom fields, node approval mode) included in one call instead of needing a follow-up
ninjaone_get_organization per org.

Args:
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - after (number, optional): Last organization ID for pagination
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        after: z.number().int().optional().describe("Last organization ID from previous page"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ page_size, after, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (after !== undefined) params["after"] = after;

        const orgs = await client.get<Organization[]>("/organizations-detailed", params);
        if (!orgs.length) return textResult("No organizations found.");

        const hasMore = orgs.length === page_size;
        const lastId = orgs[orgs.length - 1]?.id;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: orgs.length, has_more: hasMore, last_id: lastId, organizations: orgs });
        }

        const lines = [`# Organizations — Detailed (${orgs.length}${hasMore ? "+" : ""})`, ""];
        for (const org of orgs) {
          lines.push(`## ${org.name} (ID: ${org.id})`);
          if (org.description) lines.push(`- **Description**: ${org.description}`);
          lines.push(`- **Node Approval Mode**: ${org.nodeApprovalMode ?? "N/A"}`);
          if (org.tags?.length) lines.push(`- **Tags**: ${org.tags.join(", ")}`);
          lines.push("");
        }
        lines.push(paginationNote(hasMore, lastId));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Get Organization ───────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_organization",
    {
      title: "Get Organization Details",
      description: `Get full details for a specific organization by ID.

Returns name, description, tags, node approval mode, and custom fields.

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
        const client = getClient();
        const org = await client.get<Organization>(`/organization/${organization_id}`);

        if (response_format === ResponseFormat.JSON) return jsonResult(org);

        const lines = [
          `# Organization: ${org.name}`,
          "",
          `- **ID**: ${org.id}`,
          `- **Description**: ${org.description ?? "N/A"}`,
          `- **Node Approval Mode**: ${org.nodeApprovalMode ?? "N/A"}`,
          `- **Tags**: ${org.tags?.join(", ") ?? "None"}`,
        ];
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Create Organization ────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_create_organization",
    {
      title: "Create Organization",
      description: `Create a new organization (customer) in NinjaOne.

Optionally copies settings from a template organization.

Args:
  - name (string): Organization name (required)
  - description (string, optional): Organization description
  - template_organization_id (number, optional): Copy settings from this org
  - node_approval_mode (string, optional): 'AUTOMATIC' or 'MANUAL' (default: 'AUTOMATIC')`,
      inputSchema: z.object({
        name: z.string().min(1).max(200).describe("Organization name"),
        description: z.string().optional().describe("Organization description"),
        template_organization_id: z.number().int().optional().describe("Copy settings from this organization ID"),
        node_approval_mode: z.enum(["AUTOMATIC", "MANUAL"]).default("AUTOMATIC").describe("Device approval mode"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ name, description, template_organization_id, node_approval_mode }) => {
      try {
        const client = getClient();
        const body: Record<string, unknown> = { name, nodeApprovalMode: node_approval_mode };
        if (description) body["description"] = description;

        const params: Record<string, unknown> = {};
        if (template_organization_id !== undefined) params["templateOrganizationId"] = template_organization_id;

        const org = await client.post<Organization>("/organizations", body, params);
        return textResult(`✅ Organization "${name}" created successfully (ID: ${org.id}).`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Organization Locations ────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_organization_locations",
    {
      title: "List Organization Locations",
      description: `List all locations (sites/offices) for an organization.

Returns location IDs, names, and address information.

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
        const client = getClient();
        const locations = await client.get<OrganizationLocation[]>(`/organization/${organization_id}/locations`);

        if (!locations.length) return textResult(`No locations found for organization ${organization_id}.`);

        if (response_format === ResponseFormat.JSON) return jsonResult({ organization_id, count: locations.length, locations });

        const lines = [`# Locations for Organization ${organization_id} (${locations.length})`, ""];
        for (const loc of locations) {
          lines.push(`## ${loc.name} (ID: ${loc.id})`);
          const addr = [loc.address, loc.city, loc.state, loc.zip, loc.country].filter(Boolean).join(", ");
          if (addr) lines.push(`- **Address**: ${addr}`);
          if (loc.phone) lines.push(`- **Phone**: ${loc.phone}`);
          if (loc.description) lines.push(`- **Description**: ${loc.description}`);
          lines.push("");
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List All Locations (Global) ────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_locations",
    {
      title: "List All Locations",
      description: `List locations across every organization (not scoped to one org). Use
ninjaone_list_organization_locations instead when you already know the organization.

Args:
  - page_size (number, optional): Results per page, max ${MAX_PAGE_SIZE} (default: ${DEFAULT_PAGE_SIZE})
  - after (number, optional): Last location ID from previous page
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        page_size: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).describe("Results per page"),
        after: z.number().int().optional().describe("Last location ID from previous page"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ page_size, after, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = { pageSize: page_size };
        if (after !== undefined) params["after"] = after;

        const locations = await client.get<OrganizationLocation[]>("/locations", params);
        if (!locations.length) return textResult("No locations found.");

        const hasMore = locations.length === page_size;
        const lastId = locations[locations.length - 1]?.id;

        if (response_format === ResponseFormat.JSON) {
          return jsonResult({ count: locations.length, has_more: hasMore, last_id: lastId, locations });
        }

        const lines = [`# Locations (${locations.length}${hasMore ? "+" : ""})`, ""];
        for (const loc of locations) {
          lines.push(`- **${loc.name}** (ID: ${loc.id}, Org: ${loc.organizationId})`);
        }
        lines.push(paginationNote(hasMore, lastId));
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Update Organization ─────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_update_organization",
    {
      title: "Update Organization",
      description: `Update an existing organization's name, description, approval mode, or tags.

Args:
  - organization_id (number): The organization ID to update
  - name (string, optional): New name
  - description (string, optional): New description
  - node_approval_mode (string, optional): 'AUTOMATIC', 'MANUAL', or 'REJECT'
  - tags (array of strings, optional): Replace the organization's tags

Only the fields you provide are changed.`,
      inputSchema: z.object({
        organization_id: z.number().int().describe("The organization ID"),
        name: z.string().min(1).max(200).optional().describe("New organization name"),
        description: z.string().optional().describe("New description"),
        node_approval_mode: z.enum(["AUTOMATIC", "MANUAL", "REJECT"]).optional().describe("New device approval mode"),
        tags: z.array(z.string()).optional().describe("Replace the organization's tags"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ organization_id, name, description, node_approval_mode, tags }) => {
      const body: Record<string, unknown> = {};
      if (name !== undefined) body["name"] = name;
      if (description !== undefined) body["description"] = description;
      if (node_approval_mode !== undefined) body["nodeApprovalMode"] = node_approval_mode;
      if (tags !== undefined) body["tags"] = tags;

      if (Object.keys(body).length === 0) {
        return textResult("Error: No fields to update. Provide at least one of: name, description, node_approval_mode, tags.");
      }
      try {
        const client = getClient();
        await client.patch(`/organization/${organization_id}`, body);
        return textResult(`✅ Organization ${organization_id} updated: ${Object.keys(body).join(", ")}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Create Organization Location ────────────────────────────────────────────

  server.registerTool(
    "ninjaone_create_organization_location",
    {
      title: "Create Organization Location",
      description: `Add a new location (site/office) to an organization.

Args:
  - organization_id (number): The organization ID
  - name (string): Location name
  - address (string, optional): Full street address
  - description (string, optional): Location description
  - tags (array of strings, optional): Tags to apply`,
      inputSchema: z.object({
        organization_id: z.number().int().describe("The organization ID"),
        name: z.string().min(1).max(200).describe("Location name"),
        address: z.string().optional().describe("Full street address"),
        description: z.string().optional().describe("Location description"),
        tags: z.array(z.string()).optional().describe("Tags to apply"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ organization_id, name, address, description, tags }) => {
      try {
        const client = getClient();
        const body: Record<string, unknown> = { name };
        if (address) body["address"] = address;
        if (description) body["description"] = description;
        if (tags?.length) body["tags"] = tags;

        const location = await client.post<OrganizationLocation>(`/organization/${organization_id}/locations`, body);
        return textResult(`✅ Location "${name}" created for organization ${organization_id} (ID: ${location.id ?? "?"}).`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Update Organization Location ────────────────────────────────────────────

  server.registerTool(
    "ninjaone_update_organization_location",
    {
      title: "Update Organization Location",
      description: `Update an existing location's name, address, or description.

Args:
  - organization_id (number): The organization ID
  - location_id (number): The location ID to update
  - name (string, optional): New name
  - address (string, optional): New address
  - description (string, optional): New description

Only the fields you provide are changed.`,
      inputSchema: z.object({
        organization_id: z.number().int().describe("The organization ID"),
        location_id: z.number().int().describe("The location ID"),
        name: z.string().min(1).max(200).optional().describe("New location name"),
        address: z.string().optional().describe("New address"),
        description: z.string().optional().describe("New description"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ organization_id, location_id, name, address, description }) => {
      const body: Record<string, unknown> = {};
      if (name !== undefined) body["name"] = name;
      if (address !== undefined) body["address"] = address;
      if (description !== undefined) body["description"] = description;

      if (Object.keys(body).length === 0) {
        return textResult("Error: No fields to update. Provide at least one of: name, address, description.");
      }
      try {
        const client = getClient();
        await client.patch(`/organization/${organization_id}/locations/${location_id}`, body);
        return textResult(`✅ Location ${location_id} (org ${organization_id}) updated: ${Object.keys(body).join(", ")}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
