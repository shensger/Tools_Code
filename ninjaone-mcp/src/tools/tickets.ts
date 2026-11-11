import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getClient, handleApiError } from "../services/ninja-client.js";
import { textResult, jsonResult, fmtTs, ResponseFormat } from "../services/response-utils.js";
import type { TicketBoard, TicketSummary, TicketForm, TicketContact, TicketLogEntry } from "../types.js";

const ResponseFormatSchema = z
  .nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable, 'json' for machine-readable");

// NinjaOne's ticketing status/type/severity enums (distinct from the alert-severity ones used
// elsewhere — see NewTicketRequest / UpdateTicketWithComment in the public API schema).
const TICKET_STATUS = ["NEW", "OPEN", "WAITING", "PAUSED", "RESOLVED", "CLOSED"] as const;
const TICKET_TYPE = ["PROBLEM", "QUESTION", "INCIDENT", "TASK"] as const;
const TICKET_SEVERITY = ["NONE", "MINOR", "MODERATE", "MAJOR", "CRITICAL"] as const;

export function registerTicketTools(server: McpServer): void {
  // ── List Ticket Boards ─────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_ticket_boards",
    {
      title: "List Ticket Boards",
      description: `List NinjaOne's ticket boards. NinjaOne organizes tickets into boards (similar to
ConnectWise's boards/queues) rather than one flat ticket list — you need a board ID before you
can search/list tickets with ninjaone_search_tickets.

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
        const boards = await client.get<TicketBoard[]>("/ticketing/trigger/boards");
        if (!boards.length) return textResult("No ticket boards found.");
        if (response_format === ResponseFormat.JSON) return jsonResult({ count: boards.length, boards });

        const lines = [`# Ticket Boards (${boards.length})`, ""];
        for (const b of boards) lines.push(`- **${b.name ?? "(unnamed)"}** (ID: ${b.id})`);
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Search Tickets On A Board ──────────────────────────────────────────────

  server.registerTool(
    "ninjaone_search_tickets",
    {
      title: "Search Tickets On A Board",
      description: `Search/list tickets on a specific board, with optional text search and field filters.

There's no single "list all tickets" endpoint in NinjaOne — tickets are always queried through a
board. Use ninjaone_list_ticket_boards first to get a board_id.

Args:
  - board_id (number): The board to search (from ninjaone_list_ticket_boards)
  - search (string, optional): Free-text search across ticket fields
  - status (string, optional): Filter by status: NEW, OPEN, WAITING, PAUSED, RESOLVED, CLOSED
  - client_id (number, optional): Filter to one organization (NinjaOne calls this "client")
  - page_size (number, optional): Results per page (default: 25)
  - cursor (number, optional): Last ticket ID from previous page, for pagination
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        board_id: z.number().int().describe("Board ID from ninjaone_list_ticket_boards"),
        search: z.string().optional().describe("Free-text search across ticket fields"),
        status: z.enum(TICKET_STATUS).optional().describe("Filter by status"),
        client_id: z.number().int().optional().describe("Filter to one organization (client) ID"),
        page_size: z.number().int().min(1).max(200).default(25).describe("Results per page"),
        cursor: z.number().int().optional().describe("Last ticket ID from previous page"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ board_id, search, status, client_id, page_size, cursor, response_format }) => {
      try {
        const client = getClient();
        const filters: Array<{ field: string; operator: string; value: string }> = [];
        if (status) filters.push({ field: "status", operator: "eq", value: status });
        if (client_id !== undefined) filters.push({ field: "clientId", operator: "eq", value: String(client_id) });

        const body: Record<string, unknown> = { pageSize: page_size };
        if (search) body["searchCriteria"] = search;
        if (filters.length) body["filters"] = filters;
        if (cursor !== undefined) body["lastCursorId"] = cursor;

        const result = await client.post<{ results?: TicketSummary[]; tickets?: TicketSummary[] } | TicketSummary[]>(
          `/ticketing/trigger/board/${board_id}/run`,
          body
        );
        const tickets = Array.isArray(result) ? result : result.results ?? result.tickets ?? [];

        if (!tickets.length) return textResult(`No tickets found on board ${board_id} matching filters.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ board_id, count: tickets.length, tickets });

        const lines = [`# Tickets on Board ${board_id} (${tickets.length})`, ""];
        for (const t of tickets) {
          const sevIcon = t["severity"] === "CRITICAL" ? "🔴" : t["severity"] === "MAJOR" ? "🟠" : "⚪";
          lines.push(`## ${sevIcon} [${t.id}] ${t.summary ?? "(no summary)"}`);
          lines.push(`- **Status**: ${t.status ?? "N/A"} | **Type**: ${t.type ?? "N/A"} | **Severity**: ${String(t["severity"] ?? "N/A")}`);
          lines.push(`- **Client ID**: ${t.clientId ?? "N/A"} | **Device ID**: ${t.nodeId ?? "N/A"}`);
          if (t.createTime) lines.push(`- **Created**: ${fmtTs(t.createTime)}`);
          lines.push("");
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Create Ticket ──────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_create_ticket",
    {
      title: "Create Ticket",
      description: `Create a new ticket in NinjaOne.

Args:
  - summary (string): Ticket title (max 200 chars)
  - description (string, optional): Body text of the initial description
  - description_public (boolean, optional): Whether the description is client-visible (default: false — internal)
  - client_id (number, optional): Organization ("client") ID to associate
  - node_id (number, optional): Device ID to associate
  - location_id (number, optional): Location ID to associate
  - ticket_form_id (number, optional): Ticket form ID (from ninjaone_list_ticket_forms)
  - status (string, optional): NEW, OPEN, WAITING, PAUSED, RESOLVED, or CLOSED (default: NEW)
  - type (string, optional): PROBLEM, QUESTION, INCIDENT, or TASK
  - severity (string, optional): NONE, MINOR, MODERATE, MAJOR, or CRITICAL`,
      inputSchema: z.object({
        summary: z.string().min(1).max(200).describe("Ticket title/summary"),
        description: z.string().optional().describe("Body text of the initial description"),
        description_public: z.boolean().default(false).describe("Whether the description is client-visible"),
        client_id: z.number().int().optional().describe("Organization (client) ID"),
        node_id: z.number().int().optional().describe("Device ID"),
        location_id: z.number().int().optional().describe("Location ID"),
        ticket_form_id: z.number().int().optional().describe("Ticket form ID"),
        status: z.enum(TICKET_STATUS).default("NEW").describe("Initial status"),
        type: z.enum(TICKET_TYPE).optional().describe("Ticket type"),
        severity: z.enum(TICKET_SEVERITY).optional().describe("Ticket severity"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ summary, description, description_public, client_id, node_id, location_id, ticket_form_id, status, type, severity }) => {
      try {
        const client = getClient();
        const body: Record<string, unknown> = { summary, status };
        if (client_id !== undefined) body["clientId"] = client_id;
        if (node_id !== undefined) body["nodeId"] = node_id;
        if (location_id !== undefined) body["locationId"] = location_id;
        if (ticket_form_id !== undefined) body["ticketFormId"] = ticket_form_id;
        if (type) body["type"] = type;
        if (severity) body["severity"] = severity;
        if (description) body["description"] = { body: description, public: description_public };

        const ticket = await client.post<TicketSummary>("/ticketing/ticket", body);
        return textResult(`✅ Ticket created: **[#${ticket.id ?? "?"}] ${summary}** (${status})`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Update Ticket (optionally with a comment) ──────────────────────────────

  server.registerTool(
    "ninjaone_update_ticket",
    {
      title: "Update Ticket",
      description: `Update an existing ticket's status/type/severity/summary, and optionally add a comment in
the same call (NinjaOne bundles ticket updates and comments into one request).

Args:
  - ticket_id (number): The ticket ID to update
  - status (string, optional): New status
  - type (string, optional): New type
  - severity (string, optional): New severity
  - summary (string, optional): New summary/title
  - assigned_app_user_id (number, optional): Reassign to this technician's user ID
  - comment (string, optional): Comment text to add alongside the update
  - comment_public (boolean, optional): Whether the comment is client-visible (default: false — internal note)`,
      inputSchema: z.object({
        ticket_id: z.number().int().describe("The ticket ID"),
        status: z.enum(TICKET_STATUS).optional().describe("New status"),
        type: z.enum(TICKET_TYPE).optional().describe("New type"),
        severity: z.enum(TICKET_SEVERITY).optional().describe("New severity"),
        summary: z.string().min(1).max(200).optional().describe("New summary/title"),
        assigned_app_user_id: z.number().int().optional().describe("Reassign to this technician's user ID"),
        comment: z.string().optional().describe("Comment text to add alongside the update"),
        comment_public: z.boolean().default(false).describe("Whether the comment is client-visible"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ ticket_id, status, type, severity, summary, assigned_app_user_id, comment, comment_public }) => {
      const ticketFields: Record<string, unknown> = {};
      if (status) ticketFields["status"] = status;
      if (type) ticketFields["type"] = type;
      if (severity) ticketFields["severity"] = severity;
      if (summary) ticketFields["summary"] = summary;
      if (assigned_app_user_id !== undefined) ticketFields["assignedAppUserId"] = assigned_app_user_id;

      if (Object.keys(ticketFields).length === 0 && !comment) {
        return textResult("Error: nothing to update. Provide at least one field to change or a comment to add.");
      }
      try {
        const client = getClient();
        const body: Record<string, unknown> = { ticket: ticketFields };
        if (comment) body["comment"] = { body: comment, public: comment_public };

        await client.put(`/ticketing/ticket/${ticket_id}`, body);
        const changes = Object.keys(ticketFields).join(", ") || "(no field changes)";
        return textResult(`✅ Ticket #${ticket_id} updated: ${changes}${comment ? " + comment added" : ""}`);
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── Get Ticket Log Entries ──────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_get_ticket_log_entries",
    {
      title: "Get Ticket Log Entries",
      description: `Get the log entries (comments, description, status changes) on a ticket, in chronological order.

Args:
  - ticket_id (number): The ticket ID
  - entry_type (string, optional): Filter by entry type: DESCRIPTION, COMMENT, CONDITION, SAVE, DELETE
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')`,
      inputSchema: z.object({
        ticket_id: z.number().int().describe("The ticket ID"),
        entry_type: z.enum(["DESCRIPTION", "COMMENT", "CONDITION", "SAVE", "DELETE"]).optional().describe("Filter by entry type"),
        response_format: ResponseFormatSchema,
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ ticket_id, entry_type, response_format }) => {
      try {
        const client = getClient();
        const params: Record<string, unknown> = {};
        if (entry_type) params["type"] = entry_type;

        const entries = await client.get<TicketLogEntry[]>(`/ticketing/ticket/${ticket_id}/log-entry`, params);
        if (!entries.length) return textResult(`No log entries on ticket #${ticket_id}.`);
        if (response_format === ResponseFormat.JSON) return jsonResult({ ticket_id, count: entries.length, entries });

        const lines = [`# Log Entries — Ticket #${ticket_id} (${entries.length})`, ""];
        for (const e of entries) {
          const when = e.createTime ? fmtTs(e.createTime) : "N/A";
          const visibility = e.public === false ? " 🔒 (Internal)" : "";
          lines.push(`### [${when}] ${e.type ?? "Entry"}${visibility}`);
          if (e.body) lines.push(e.body);
          lines.push("");
        }
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Ticket Forms ────────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_ticket_forms",
    {
      title: "List Ticket Forms",
      description: `List the ticket forms configured in NinjaOne — needed for ticket_form_id when creating a
ticket with a specific form's fields.

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
        const forms = await client.get<TicketForm[]>("/ticketing/ticket-form");
        if (!forms.length) return textResult("No ticket forms found.");
        if (response_format === ResponseFormat.JSON) return jsonResult({ count: forms.length, forms });

        const lines = [`# Ticket Forms (${forms.length})`, ""];
        for (const f of forms) lines.push(`- **${f.name ?? "(unnamed)"}** (ID: ${f.id})`);
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );

  // ── List Ticket Contacts ─────────────────────────────────────────────────────

  server.registerTool(
    "ninjaone_list_ticket_contacts",
    {
      title: "List Ticket Contacts",
      description: `List end-user contacts available for tickets (e.g. as ticket requesters).

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
        const contacts = await client.get<TicketContact[]>("/ticketing/contact/contacts");
        if (!contacts.length) return textResult("No ticket contacts found.");
        if (response_format === ResponseFormat.JSON) return jsonResult({ count: contacts.length, contacts });

        const lines = [`# Ticket Contacts (${contacts.length})`, ""];
        for (const c of contacts) lines.push(`- **${c.name ?? "(unnamed)"}** — ${c.email ?? "N/A"}${c.clientId ? ` (Client ${c.clientId})` : ""}`);
        return textResult(lines.join("\n"));
      } catch (err) {
        return textResult(handleApiError(err));
      }
    }
  );
}
