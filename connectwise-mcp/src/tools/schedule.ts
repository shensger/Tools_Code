/**
 * Schedule module tools: schedule entries (dispatch / calendar bookings), schedule types and statuses.
 *
 * A schedule entry is a *booking* of a member's time against a ticket or activity. It is NOT a time
 * entry — booking a tech does not log billable time. Use cw_create_time_entry for actual work done.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { cwDelete, cwGet, cwList, cwPatch, cwPost, toPatchOps } from "../services/client.js";
import {
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
import type { CwInfo, CwRef } from "../types.js";

interface ScheduleEntry {
  id: number;
  objectId?: number;
  name?: string;
  member?: CwRef;
  where?: CwRef;
  dateStart?: string;
  dateEnd?: string;
  reminder?: CwRef;
  status?: CwRef;
  type?: CwRef;
  span?: CwRef;
  doneFlag?: boolean;
  acknowledgedFlag?: boolean;
  ownerFlag?: boolean;
  meetingFlag?: boolean;
  allowScheduleConflictsFlag?: boolean;
  closeDate?: string;
  hours?: number;
  _info?: CwInfo;
}

interface ScheduleType {
  id: number;
  name: string;
  identifier?: string;
  chargeCode?: CwRef;
  where?: CwRef;
  systemFlag?: boolean;
  _info?: CwInfo;
}

interface ScheduleStatus {
  id: number;
  name: string;
  defaultFlag?: boolean;
  showAsTentativeFlag?: boolean;
  _info?: CwInfo;
}

function entryLine(e: ScheduleEntry): string {
  return `- **#${e.id}** ${e.member?.identifier ?? e.member?.name ?? "?"} · ${when(e.dateStart)} → ${when(e.dateEnd)}${e.hours !== undefined ? ` · ${hours(e.hours)}` : ""} · ${e.type?.name ?? e.type?.identifier ?? "?"} #${e.objectId ?? "?"} · ${e.name ?? ""} · ${e.status?.name ?? ""}${e.doneFlag ? " · _done_" : ""}`;
}

function entryDetail(e: ScheduleEntry): string {
  return [
    `# Schedule entry #${e.id}`,
    kv([
      ["Name", e.name],
      ["Member", ref(e.member)],
      ["Type", ref(e.type)],
      ["Object (ticket/activity) ID", e.objectId],
      ["Start", when(e.dateStart)],
      ["End", when(e.dateEnd)],
      ["Hours", e.hours !== undefined ? hours(e.hours) : undefined],
      ["Status", ref(e.status)],
      ["Where", ref(e.where)],
      ["Reminder", e.reminder?.name],
      ["Done", e.doneFlag ? "yes" : undefined],
      ["Acknowledged", e.acknowledgedFlag ? "yes" : undefined],
      ["Close date", e.closeDate ? when(e.closeDate) : undefined],
    ]),
  ].join("\n");
}

export function registerScheduleTools(server: McpServer): void {
  server.registerTool(
    "cw_search_schedule_entries",
    {
      title: "Search Schedule Entries",
      description: `Search the dispatch calendar (schedule entries / bookings). A booking reserves a member's time on a ticket or activity; it is not logged time.

Condition examples:
  - Who is booked tomorrow: dateStart>=[2025-06-06T00:00:00Z] and dateStart<[2025-06-07T00:00:00Z]
  - A member's bookings: member/identifier="shensger" and dateStart>=[2025-06-02T00:00:00Z]
  - Bookings on a ticket: objectId=12345 and type/identifier="S"
  - Open bookings: doneFlag=false

Dates are UTC.`,
      inputSchema: { ...listFilterSchema, response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<ScheduleEntry>(
        "schedule/entries",
        {
          conditions: a.conditions,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "dateStart asc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      return listResult(paged, a.response_format, {
        title: `Schedule entries${a.conditions ? ` where ${a.conditions}` : ""}`,
        itemKey: "schedule_entries",
        renderItem: entryLine,
      });
    }),
  );

  server.registerTool(
    "cw_get_schedule_entry",
    {
      title: "Get Schedule Entry",
      description: `Get one schedule entry (booking) by ID.`,
      inputSchema: {
        scheduleEntryId: z.number().int().positive().describe("Schedule entry ID"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const e = await cwGet<ScheduleEntry>(`schedule/entries/${a.scheduleEntryId}`);
      return recordResult(e, a.response_format, entryDetail);
    }),
  );

  server.registerTool(
    "cw_create_schedule_entry",
    {
      title: "Create Schedule Entry (book a tech)",
      description: `Book a member on a service ticket, project ticket or activity (dispatch). This puts it on their calendar; it does NOT log time.
Times are ISO 8601 UTC — convert from the member's local time zone first.
type_identifier is the schedule type: typically "S" = service ticket, "P" = project ticket, "C" = activity. Confirm with cw_list_schedule_types if unsure.
Set allow_conflicts=true to book over an existing booking.`,
      inputSchema: {
        object_id: z.number().int().positive().describe("Ticket ID (or activity ID) being scheduled"),
        type_identifier: z.string().default("S").describe('Schedule type identifier, e.g. "S" (service), "P" (project), "C" (activity)'),
        type_id: z.number().int().optional().describe("Schedule type ID (overrides type_identifier)"),
        member_id: z.number().int().optional(),
        member_identifier: z.string().optional().describe('Member identifier (login) to book, e.g. "shensger"'),
        date_start: z.string().describe("Start, ISO 8601 UTC"),
        date_end: z.string().describe("End, ISO 8601 UTC"),
        name: z.string().optional().describe("Calendar title (defaults to the ticket summary)"),
        status_name: z.string().optional().describe('Schedule status name, e.g. "Firm" or "Tentative"'),
        where_id: z.number().int().optional().describe("Service location ID (e.g. On-Site / Remote)"),
        allow_conflicts: z.boolean().default(false).describe("Allow overlapping an existing booking"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    safe(async (a) => {
      if (a.member_id === undefined && !a.member_identifier) {
        return textResult("Error: provide member_id or member_identifier for the person being booked.");
      }
      const body: Record<string, unknown> = {
        objectId: a.object_id,
        type: a.type_id !== undefined ? { id: a.type_id } : { identifier: a.type_identifier },
        member: nameRef(a.member_id, a.member_identifier, "identifier"),
        dateStart: a.date_start,
        dateEnd: a.date_end,
        name: a.name,
        status: a.status_name ? { name: a.status_name } : undefined,
        where: a.where_id !== undefined ? { id: a.where_id } : undefined,
        allowScheduleConflictsFlag: a.allow_conflicts,
      };
      const created = await cwPost<ScheduleEntry>("schedule/entries", body);
      return recordResult(created, a.response_format, (e) => `Created schedule entry.\n\n${entryDetail(e)}`);
    }),
  );

  server.registerTool(
    "cw_update_schedule_entry",
    {
      title: "Update Schedule Entry",
      description: `Move or modify a booking: change start/end (reschedule), reassign member, change status, or mark done. Only the fields you pass are changed. Times are ISO 8601 UTC.`,
      inputSchema: {
        scheduleEntryId: z.number().int().positive(),
        date_start: z.string().optional(),
        date_end: z.string().optional(),
        member_id: z.number().int().optional(),
        member_identifier: z.string().optional(),
        status_name: z.string().optional(),
        name: z.string().optional(),
        done: z.boolean().optional().describe("Mark the booking done / not done"),
        allow_conflicts: z.boolean().optional(),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const ops = toPatchOps({
        dateStart: a.date_start,
        dateEnd: a.date_end,
        member: nameRef(a.member_id, a.member_identifier, "identifier"),
        status: a.status_name ? { name: a.status_name } : undefined,
        name: a.name,
        doneFlag: a.done,
        allowScheduleConflictsFlag: a.allow_conflicts,
      });
      if (!ops.length) return textResult("Nothing to update — pass at least one field.");
      const updated = await cwPatch<ScheduleEntry>(`schedule/entries/${a.scheduleEntryId}`, ops);
      return recordResult(updated, a.response_format, (e) => `Updated schedule entry.\n\n${entryDetail(e)}`);
    }),
  );

  server.registerTool(
    "cw_delete_schedule_entry",
    {
      title: "Delete Schedule Entry",
      description: `Remove a booking from the dispatch calendar. This cannot be undone. Confirm with the user before calling.`,
      inputSchema: { scheduleEntryId: z.number().int().positive() },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      await cwDelete(`schedule/entries/${a.scheduleEntryId}`);
      return textResult(`Deleted schedule entry #${a.scheduleEntryId}.`, { deleted: a.scheduleEntryId });
    }),
  );

  server.registerTool(
    "cw_list_schedule_types",
    {
      title: "List Schedule Types and Statuses",
      description: `List schedule types (identifier S/P/C etc. used by cw_create_schedule_entry) and schedule statuses (e.g. Firm, Tentative).`,
      inputSchema: { ...paginationSchema, response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const [types, statuses] = await Promise.all([
        cwList<ScheduleType>("schedule/types", { page: a.page, pageSize: a.pageSize, orderBy: "name asc" }),
        cwList<ScheduleStatus>("schedule/statuses", { page: 1, pageSize: 100, orderBy: "name asc" }),
      ]);
      const structured = { schedule_types: types.items, schedule_statuses: statuses.items };
      if (a.response_format === "json") return textResult(JSON.stringify(structured, null, 2), structured);
      const text = [
        "# Schedule types",
        ...types.items.map((t) => `- **${t.name}** (#${t.id}) identifier \`${t.identifier ?? "?"}\`${t.systemFlag ? " · system" : ""}`),
        "",
        "# Schedule statuses",
        ...statuses.items.map((s) => `- **${s.name}** (#${s.id})${s.defaultFlag ? " · default" : ""}${s.showAsTentativeFlag ? " · tentative" : ""}`),
      ].join("\n");
      return textResult(text, structured);
    }),
  );
}
