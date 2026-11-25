/**
 * Service module tools: tickets, ticket notes, boards, statuses, types, priorities.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { cwDelete, cwGet, cwList, cwPatch, cwPost, toPatchOps } from "../services/client.js";
import {
  clip,
  hours,
  kv,
  listFilterSchema,
  listResult,
  nameRef,
  paginationSchema,
  recordResult,
  ref,
  responseFormatSchema,
  safe,
  textResult,
  when,
} from "../services/format.js";
import type { Board, BoardStatus, BoardType, Configuration, Priority, Ticket, TicketNote, TimeEntry } from "../types.js";

/* ------------------------------------------------------------------ */
/* Renderers                                                           */
/* ------------------------------------------------------------------ */

function ticketLine(t: Ticket): string {
  return `- **#${t.id}** ${t.summary} — ${t.status?.name ?? "?"} | ${t.company?.name ?? "?"} | ${t.board?.name ?? "?"} | pri: ${t.priority?.name ?? "?"} | owner: ${t.owner?.identifier ?? t.owner?.name ?? "unassigned"} | entered ${when(t.dateEntered)}`;
}

function ticketDetail(t: Ticket): string {
  return [
    `# Ticket #${t.id}: ${t.summary}`,
    kv([
      ["Status", ref(t.status)],
      ["Board", ref(t.board)],
      ["Company", ref(t.company)],
      ["Site", ref(t.site)],
      ["Contact", t.contactName ? `${t.contactName}${t.contactEmailAddress ? ` <${t.contactEmailAddress}>` : ""}${t.contact ? ` (#${t.contact.id})` : ""}` : ref(t.contact)],
      ["Contact phone", t.contactPhoneNumber],
      ["Type / Subtype / Item", [t.type?.name, t.subType?.name, t.item?.name].filter(Boolean).join(" / ")],
      ["Priority", ref(t.priority)],
      ["Severity / Impact", [t.severity, t.impact].filter(Boolean).join(" / ")],
      ["Owner", ref(t.owner)],
      ["Team", ref(t.team)],
      ["Resources", t.resources],
      ["Source", ref(t.source)],
      ["Agreement", ref(t.agreement)],
      ["Service location", ref(t.serviceLocation)],
      ["Budget / Actual hours", `${hours(t.budgetHours)} / ${hours(t.actualHours)}`],
      ["Required date", when(t.requiredDate)],
      ["Entered", `${when(t.dateEntered)} by ${t.enteredBy ?? "?"}`],
      ["Responded", when(t.dateResponded)],
      ["Resolved", when(t.dateResolved)],
      ["Closed", t.closedFlag ? `${when(t.closedDate)} by ${t.closedBy ?? "?"}` : "no"],
      ["SLA status", t.slaStatus],
      ["Parent ticket", t.parentTicketId],
      ["Has child tickets", t.hasChildTicket ? "yes" : undefined],
      ["Last updated", t._info?.lastUpdated ? `${when(t._info.lastUpdated)} by ${t._info.updatedBy ?? "?"}` : undefined],
    ]),
    t.customFields?.length
      ? `\n**Custom fields**\n${t.customFields
          .filter((c) => c.value !== undefined && c.value !== null && c.value !== "")
          .map((c) => `- ${c.caption ?? c.id}: ${String(c.value)}`)
          .join("\n")}`
      : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function noteKind(n: TicketNote): string {
  const kinds: string[] = [];
  if (n.detailDescriptionFlag) kinds.push("Discussion");
  if (n.internalAnalysisFlag) kinds.push("Internal");
  if (n.resolutionFlag) kinds.push("Resolution");
  return kinds.length ? kinds.join("+") : "Note";
}

function noteBlock(n: TicketNote): string {
  const author = n.member?.identifier ?? n.member?.name ?? n.contact?.name ?? n.createdBy ?? "?";
  return `### Note #${n.id} · ${noteKind(n)} · ${author} · ${when(n.dateCreated)}\n${clip(n.text, 1500) || "_(empty)_"}\n`;
}

function timeEntryLine(te: TimeEntry): string {
  return `- **#${te.id}** ${te.member?.identifier ?? te.member?.name ?? "?"} · ${when(te.timeStart)} → ${when(te.timeEnd)} · ${hours(te.actualHours)} · ${te.workType?.name ?? "?"} · ${te.billableOption ?? ""}\n  ${clip(te.notes, 300)}`;
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

export function registerServiceTools(server: McpServer): void {
  /* ---------------- Tickets ---------------- */

  server.registerTool(
    "cw_search_tickets",
    {
      title: "Search Service Tickets",
      description: `Search ConnectWise Manage service tickets with a conditions filter, sorting and pagination.

Common condition examples:
  - Open tickets on a board: board/name="Help Desk" and closedFlag=false
  - Assigned to me: owner/identifier="shensger" and closedFlag=false   (or resources contains "shensger")
  - By company: company/identifier="YELLOWBRICK" and closedFlag=false
  - By status set: status/name in ("New","Needs Attention")
  - Keyword: summary like "%VPN%"
  - Recently updated: _info/lastUpdated>[2025-06-01T00:00:00Z]
  - High priority: priority/name contains "1" or priority/sortOrder<=2

Returns a paged list of tickets (id, summary, status, company, board, priority, owner, dateEntered). Use cw_get_ticket for full details and cw_list_ticket_notes for the conversation.`,
      inputSchema: {
        ...listFilterSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<Ticket>(
        "service/tickets",
        {
          conditions: a.conditions,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "dateEntered desc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      return listResult(paged, a.response_format, {
        title: `Tickets${a.conditions ? ` where ${a.conditions}` : ""}`,
        itemKey: "tickets",
        renderItem: ticketLine,
      });
    }),
  );

  server.registerTool(
    "cw_get_ticket",
    {
      title: "Get Service Ticket",
      description: `Get full details of one service ticket by ID: status, board, company, contact, type/subtype/item, priority, owner, resources, hours, SLA dates, custom fields.
Does not include notes or time entries — use cw_list_ticket_notes and cw_list_ticket_time_entries for those.`,
      inputSchema: {
        ticketId: z.number().int().positive().describe("Ticket ID"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const t = await cwGet<Ticket>(`service/tickets/${a.ticketId}`);
      return recordResult(t, a.response_format, ticketDetail);
    }),
  );

  server.registerTool(
    "cw_create_ticket",
    {
      title: "Create Service Ticket",
      description: `Create a new service ticket. Requires a summary, a board (id or name) and a company (id or identifier).
Optional: initial description (becomes the first Discussion note), status, priority, type/subtype/item, contact, site, owner, source, severity/impact, required date.
Names are resolved server-side, so board_name="Help Desk" works without looking up the ID. Returns the created ticket.`,
      inputSchema: {
        summary: z.string().min(1).max(100).describe("Ticket summary/title (max 100 chars — ConnectWise limit)"),
        board_id: z.number().int().optional().describe("Board ID"),
        board_name: z.string().optional().describe("Board name (alternative to board_id)"),
        company_id: z.number().int().optional().describe("Company ID"),
        company_identifier: z.string().optional().describe("Company identifier (alternative to company_id), e.g. \"YELLOWBRICK\""),
        initial_description: z.string().optional().describe("Initial description / problem details (first Discussion note)"),
        initial_internal_analysis: z.string().optional().describe("Initial internal-only analysis note"),
        status_id: z.number().int().optional().describe("Status ID (must belong to the board)"),
        status_name: z.string().optional().describe("Status name, e.g. \"New\""),
        priority_id: z.number().int().optional().describe("Priority ID"),
        priority_name: z.string().optional().describe("Priority name, e.g. \"Priority 3 - Normal Response\""),
        type_id: z.number().int().optional().describe("Board type ID"),
        type_name: z.string().optional().describe("Board type name"),
        subtype_id: z.number().int().optional().describe("Board subtype ID"),
        subtype_name: z.string().optional().describe("Board subtype name"),
        item_id: z.number().int().optional().describe("Board item ID"),
        item_name: z.string().optional().describe("Board item name"),
        contact_id: z.number().int().optional().describe("Contact ID"),
        contact_name: z.string().optional().describe("Free-text contact name (if no contact record)"),
        contact_email: z.string().optional().describe("Free-text contact email"),
        contact_phone: z.string().optional().describe("Free-text contact phone"),
        site_id: z.number().int().optional().describe("Company site ID"),
        owner_id: z.number().int().optional().describe("Owner member ID"),
        owner_identifier: z.string().optional().describe("Owner member identifier (login), e.g. \"shensger\""),
        source_id: z.number().int().optional().describe("Ticket source ID"),
        source_name: z.string().optional().describe("Ticket source name, e.g. \"Email\", \"Phone\""),
        severity: z.enum(["Low", "Medium", "High"]).optional().describe("Severity"),
        impact: z.enum(["Low", "Medium", "High"]).optional().describe("Impact"),
        agreement_id: z.number().int().optional().describe("Agreement ID"),
        required_date: z.string().optional().describe("Required-by date, ISO 8601 (e.g. 2025-07-01T17:00:00Z)"),
        budget_hours: z.number().min(0).optional().describe("Budget hours"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    safe(async (a) => {
      const board = nameRef(a.board_id, a.board_name);
      const company = nameRef(a.company_id, a.company_identifier, "identifier");
      if (!board) return textResult("Error: board_id or board_name is required. Use cw_list_boards to find boards.");
      if (!company) return textResult("Error: company_id or company_identifier is required. Use cw_search_companies to find companies.");

      const body: Record<string, unknown> = {
        summary: a.summary,
        board,
        company,
        initialDescription: a.initial_description,
        initialInternalAnalysis: a.initial_internal_analysis,
        status: nameRef(a.status_id, a.status_name),
        priority: nameRef(a.priority_id, a.priority_name),
        type: nameRef(a.type_id, a.type_name),
        subType: nameRef(a.subtype_id, a.subtype_name),
        item: nameRef(a.item_id, a.item_name),
        contact: a.contact_id !== undefined ? { id: a.contact_id } : undefined,
        contactName: a.contact_name,
        contactEmailAddress: a.contact_email,
        contactPhoneNumber: a.contact_phone,
        site: a.site_id !== undefined ? { id: a.site_id } : undefined,
        owner: nameRef(a.owner_id, a.owner_identifier, "identifier"),
        source: nameRef(a.source_id, a.source_name),
        severity: a.severity,
        impact: a.impact,
        agreement: a.agreement_id !== undefined ? { id: a.agreement_id } : undefined,
        requiredDate: a.required_date,
        budgetHours: a.budget_hours,
      };
      for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];

      const t = await cwPost<Ticket>("service/tickets", body);
      return recordResult(t, a.response_format, (x) => `Created ticket #${x.id}.\n\n${ticketDetail(x)}`);
    }),
  );

  server.registerTool(
    "cw_update_ticket",
    {
      title: "Update Service Ticket",
      description: `Update fields on an existing ticket (JSON Patch replace). Only the fields you pass are changed.
Typical uses: change status (status_name="Completed"), reassign (owner_identifier), set priority, edit summary, set board/type, close (closedFlag via status), set budget hours.
To add a note or reply, use cw_add_ticket_note instead. Returns the updated ticket.`,
      inputSchema: {
        ticketId: z.number().int().positive().describe("Ticket ID"),
        summary: z.string().min(1).max(100).optional().describe("New summary (max 100 chars)"),
        status_id: z.number().int().optional().describe("New status ID"),
        status_name: z.string().optional().describe("New status name (must exist on the ticket's board)"),
        board_id: z.number().int().optional().describe("Move to board ID"),
        board_name: z.string().optional().describe("Move to board by name"),
        priority_id: z.number().int().optional().describe("Priority ID"),
        priority_name: z.string().optional().describe("Priority name"),
        type_id: z.number().int().optional(),
        type_name: z.string().optional(),
        subtype_id: z.number().int().optional(),
        subtype_name: z.string().optional(),
        item_id: z.number().int().optional(),
        item_name: z.string().optional(),
        owner_id: z.number().int().optional().describe("Owner member ID"),
        owner_identifier: z.string().optional().describe("Owner member identifier (login)"),
        contact_id: z.number().int().optional(),
        company_id: z.number().int().optional(),
        site_id: z.number().int().optional(),
        agreement_id: z.number().int().optional(),
        severity: z.enum(["Low", "Medium", "High"]).optional(),
        impact: z.enum(["Low", "Medium", "High"]).optional(),
        required_date: z.string().optional().describe("ISO 8601"),
        budget_hours: z.number().min(0).optional(),
        resources: z.string().optional().describe("Comma-separated member identifiers to set as resources"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const ops = toPatchOps({
        summary: a.summary,
        status: nameRef(a.status_id, a.status_name),
        board: nameRef(a.board_id, a.board_name),
        priority: nameRef(a.priority_id, a.priority_name),
        type: nameRef(a.type_id, a.type_name),
        subType: nameRef(a.subtype_id, a.subtype_name),
        item: nameRef(a.item_id, a.item_name),
        owner: nameRef(a.owner_id, a.owner_identifier, "identifier"),
        contact: a.contact_id !== undefined ? { id: a.contact_id } : undefined,
        company: a.company_id !== undefined ? { id: a.company_id } : undefined,
        site: a.site_id !== undefined ? { id: a.site_id } : undefined,
        agreement: a.agreement_id !== undefined ? { id: a.agreement_id } : undefined,
        severity: a.severity,
        impact: a.impact,
        requiredDate: a.required_date,
        budgetHours: a.budget_hours,
        resources: a.resources,
      });
      if (!ops.length) return textResult("Error: no fields to update were provided.");
      const t = await cwPatch<Ticket>(`service/tickets/${a.ticketId}`, ops);
      return recordResult(t, a.response_format, (x) => `Updated ticket #${x.id} (${ops.map((o) => o.path.slice(1)).join(", ")}).\n\n${ticketDetail(x)}`);
    }),
  );

  /* ---------------- Notes ---------------- */

  server.registerTool(
    "cw_list_ticket_notes",
    {
      title: "List Ticket Notes",
      description: `List the notes (conversation history) on a ticket, oldest first by default. Each note is flagged as Discussion (customer-visible), Internal (internal analysis) and/or Resolution.
Use this to read the full history before replying or summarizing a ticket.`,
      inputSchema: {
        ticketId: z.number().int().positive().describe("Ticket ID"),
        conditions: z.string().optional().describe(`Optional filter, e.g. internalAnalysisFlag=true or dateCreated>[2025-06-01T00:00:00Z]`),
        orderBy: z.string().default("dateCreated asc").describe("Sort, default 'dateCreated asc'"),
        ...paginationSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<TicketNote>(`service/tickets/${a.ticketId}/notes`, {
        conditions: a.conditions,
        orderBy: a.orderBy,
        page: a.page,
        pageSize: a.pageSize,
      });
      return listResult(paged, a.response_format, {
        title: `Notes on ticket #${a.ticketId}`,
        itemKey: "notes",
        renderItem: noteBlock,
        emptyMessage: `Ticket #${a.ticketId} has no notes matching the filter.`,
      });
    }),
  );

  server.registerTool(
    "cw_add_ticket_note",
    {
      title: "Add Ticket Note",
      description: `Add a note to a ticket. Choose where it appears:
  - discussion=true  → Discussion tab (visible to the customer on portal/emails)
  - internal=true    → Internal Analysis tab (internal only)
  - resolution=true  → Resolution tab
At least one must be true (default: internal=true if none specified). Set customer_updated=true to indicate the note came from the customer; set process_notifications=false to suppress email notifications. Returns the created note.`,
      inputSchema: {
        ticketId: z.number().int().positive().describe("Ticket ID"),
        text: z.string().min(1).describe("Note body (plain text)"),
        discussion: z.boolean().default(false).describe("Post to Discussion (customer-visible)"),
        internal: z.boolean().default(false).describe("Post to Internal Analysis (internal only)"),
        resolution: z.boolean().default(false).describe("Post to Resolution"),
        customer_updated: z.boolean().default(false).describe("Mark as a customer update"),
        process_notifications: z.boolean().default(true).describe("Send configured notifications for this note"),
        member_identifier: z.string().optional().describe("Post as this member (identifier). Defaults to the API member."),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    safe(async (a) => {
      const internal = a.internal || (!a.discussion && !a.resolution);
      const body: Record<string, unknown> = {
        text: a.text,
        detailDescriptionFlag: a.discussion,
        internalAnalysisFlag: internal,
        resolutionFlag: a.resolution,
        customerUpdatedFlag: a.customer_updated,
        processNotifications: a.process_notifications,
      };
      if (a.member_identifier) body.member = { identifier: a.member_identifier };
      const n = await cwPost<TicketNote>(`service/tickets/${a.ticketId}/notes`, body);
      return recordResult(n, a.response_format, (x) => `Added ${noteKind(x)} note #${x.id} to ticket #${a.ticketId}.\n\n${noteBlock(x)}`);
    }),
  );

  /* ---------------- Ticket sub-resources ---------------- */

  server.registerTool(
    "cw_list_ticket_time_entries",
    {
      title: "List Ticket Time Entries",
      description: `List time entries logged against a ticket (member, start/end, hours, work type, billable option, notes). Use to total effort on a ticket or review who worked it.`,
      inputSchema: {
        ticketId: z.number().int().positive().describe("Ticket ID"),
        ...paginationSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<TimeEntry>("time/entries", {
        conditions: `chargeToType="ServiceTicket" and chargeToId=${a.ticketId}`,
        orderBy: "timeStart asc",
        page: a.page,
        pageSize: a.pageSize,
      });
      const total = paged.items.reduce((s, e) => s + (e.actualHours ?? 0), 0);
      const result = listResult(paged, a.response_format, {
        title: `Time entries on ticket #${a.ticketId} (this page: ${hours(total)})`,
        itemKey: "time_entries",
        renderItem: timeEntryLine,
        emptyMessage: `No time entries on ticket #${a.ticketId}.`,
      });
      if (result.structuredContent) result.structuredContent.page_total_hours = total;
      return result;
    }),
  );

  server.registerTool(
    "cw_list_ticket_configurations",
    {
      title: "List Ticket Configurations",
      description: `List configurations (assets/devices) attached to a ticket.`,
      inputSchema: {
        ticketId: z.number().int().positive().describe("Ticket ID"),
        ...paginationSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<Configuration>(`service/tickets/${a.ticketId}/configurations`, { page: a.page, pageSize: a.pageSize });
      return listResult(paged, a.response_format, {
        title: `Configurations attached to ticket #${a.ticketId}`,
        itemKey: "configurations",
        renderItem: (c) => `- **${c.name}** (#${c.id}) — ${c.type?.name ?? "?"} · ${c.status?.name ?? ""} · ${c.company?.name ?? ""}`,
        emptyMessage: `No configurations attached to ticket #${a.ticketId}.`,
      });
    }),
  );

  server.registerTool(
    "cw_attach_ticket_configuration",
    {
      title: "Attach Configuration to Ticket",
      description: `Attach an existing configuration (asset) to a ticket by configuration ID.`,
      inputSchema: {
        ticketId: z.number().int().positive().describe("Ticket ID"),
        configurationId: z.number().int().positive().describe("Configuration ID (from cw_search_configurations)"),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const c = await cwPost<Configuration>(`service/tickets/${a.ticketId}/configurations`, { id: a.configurationId });
      return textResult(`Attached configuration ${ref(c)} to ticket #${a.ticketId}.`, c as unknown as Record<string, unknown>);
    }),
  );

  server.registerTool(
    "cw_detach_ticket_configuration",
    {
      title: "Detach Configuration from Ticket",
      description: `Remove a configuration (asset) from a ticket. Does not delete the configuration itself.`,
      inputSchema: {
        ticketId: z.number().int().positive().describe("Ticket ID"),
        configurationId: z.number().int().positive().describe("Configuration ID"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      await cwDelete(`service/tickets/${a.ticketId}/configurations/${a.configurationId}`);
      return textResult(`Detached configuration #${a.configurationId} from ticket #${a.ticketId}.`);
    }),
  );

  /* ---------------- Boards / statuses / types / priorities ---------------- */

  server.registerTool(
    "cw_list_boards",
    {
      title: "List Service Boards",
      description: `List service boards (e.g. "Help Desk", "Projects", "Alerts"). Board IDs/names are needed to create tickets and to look up statuses/types. Inactive boards are excluded by default.`,
      inputSchema: {
        include_inactive: z.boolean().default(false).describe("Include inactive boards"),
        conditions: z.string().optional().describe(`Extra filter, e.g. name like "%Desk%"`),
        ...paginationSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const conds = [a.include_inactive ? undefined : "inactiveFlag=false", a.conditions].filter(Boolean).join(" and ");
      const paged = await cwList<Board>("service/boards", { conditions: conds || undefined, orderBy: "name asc", page: a.page, pageSize: a.pageSize });
      return listResult(paged, a.response_format, {
        title: "Service boards",
        itemKey: "boards",
        renderItem: (b) => `- **${b.name}** (#${b.id})${b.inactiveFlag ? " _(inactive)_" : ""}${b.projectFlag ? " · project board" : ""}`,
      });
    }),
  );

  server.registerTool(
    "cw_list_board_statuses",
    {
      title: "List Board Statuses",
      description: `List the statuses defined on a board (e.g. New, In Progress, Waiting Customer, Completed) with their closed/default flags and sort order. Required to know valid status names before updating a ticket.`,
      inputSchema: {
        boardId: z.number().int().positive().describe("Board ID (from cw_list_boards)"),
        include_inactive: z.boolean().default(false).describe("Include inactive statuses"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<BoardStatus>(`service/boards/${a.boardId}/statuses`, {
        conditions: a.include_inactive ? undefined : "inactiveFlag=false",
        orderBy: "sortOrder asc",
        pageSize: 200,
      });
      return listResult(paged, a.response_format, {
        title: `Statuses on board #${a.boardId}`,
        itemKey: "statuses",
        renderItem: (s) =>
          `- **${s.name}** (#${s.id})${s.closedStatus ? " · closed" : ""}${s.defaultFlag ? " · default" : ""}${s.timeEntryNotAllowed ? " · no time entry" : ""}${s.inactiveFlag ? " · inactive" : ""}`,
      });
    }),
  );

  server.registerTool(
    "cw_list_board_types",
    {
      title: "List Board Types / Subtypes / Items",
      description: `List the types, subtypes or items configured on a board (the Type/Subtype/Item categorisation used on tickets).`,
      inputSchema: {
        boardId: z.number().int().positive().describe("Board ID"),
        kind: z.enum(["types", "subtypes", "items"]).default("types").describe("Which list to return"),
        include_inactive: z.boolean().default(false),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<BoardType>(`service/boards/${a.boardId}/${a.kind}`, {
        conditions: a.include_inactive ? undefined : "inactiveFlag=false",
        orderBy: "name asc",
        pageSize: 500,
      });
      return listResult(paged, a.response_format, {
        title: `${a.kind} on board #${a.boardId}`,
        itemKey: a.kind,
        renderItem: (t) => `- **${t.name}** (#${t.id})${t.defaultFlag ? " · default" : ""}${t.inactiveFlag ? " · inactive" : ""}`,
      });
    }),
  );

  server.registerTool(
    "cw_list_priorities",
    {
      title: "List Ticket Priorities",
      description: `List ticket priorities (e.g. "Priority 1 - Emergency Response") with sort order. Use the names/IDs when creating or updating tickets.`,
      inputSchema: { response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<Priority>("service/priorities", { orderBy: "sortOrder asc", pageSize: 100 });
      return listResult(paged, a.response_format, {
        title: "Ticket priorities",
        itemKey: "priorities",
        renderItem: (p) => `- **${p.name}** (#${p.id})${p.defaultFlag ? " · default" : ""}${p.color ? ` · ${p.color}` : ""}`,
      });
    }),
  );
}
