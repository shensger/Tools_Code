/**
 * Time module tools: time entries, work types, work roles, members.
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
import type { Member, SystemInfo, TimeEntry, WorkRole, WorkType } from "../types.js";

/* ------------------------------------------------------------------ */
/* Renderers                                                           */
/* ------------------------------------------------------------------ */

function chargeTo(te: TimeEntry): string {
  if (te.chargeToType === "ServiceTicket" || te.chargeToType === "ProjectTicket") {
    return `ticket #${te.chargeToId}${te.ticket?.summary ? ` (${clip(te.ticket.summary, 60)})` : ""}`;
  }
  return `${te.chargeToType ?? "?"} #${te.chargeToId ?? "?"}`;
}

function timeEntryLine(te: TimeEntry): string {
  return `- **#${te.id}** ${te.member?.identifier ?? te.member?.name ?? "?"} · ${when(te.timeStart)} → ${when(te.timeEnd)} · **${hours(te.actualHours)}** · ${chargeTo(te)} · ${te.company?.name ?? ""} · ${te.workType?.name ?? "?"} · ${te.billableOption ?? ""}${te.status ? ` · ${te.status}` : ""}\n  ${clip(te.notes, 200)}`;
}

function timeEntryDetail(te: TimeEntry): string {
  return [
    `# Time entry #${te.id}`,
    kv([
      ["Member", ref(te.member)],
      ["Charged to", chargeTo(te)],
      ["Company", ref(te.company)],
      ["Start", when(te.timeStart)],
      ["End", when(te.timeEnd)],
      ["Actual hours", hours(te.actualHours)],
      ["Hours deducted", te.hoursDeduct ? hours(te.hoursDeduct) : undefined],
      ["Work type", ref(te.workType)],
      ["Work role", ref(te.workRole)],
      ["Agreement", ref(te.agreement)],
      ["Billable option", te.billableOption],
      ["Status", te.status],
      ["Hours billed / invoiced", te.hoursBilled !== undefined || te.invoiceHours !== undefined ? `${hours(te.hoursBilled)} / ${hours(te.invoiceHours)}` : undefined],
      ["Added to", [te.addToDetailDescriptionFlag && "Discussion", te.addToInternalAnalysisFlag && "Internal", te.addToResolutionFlag && "Resolution"].filter(Boolean).join(", ")],
      ["Entered", `${when(te.dateEntered)} by ${te.enteredBy ?? "?"}`],
    ]),
    te.notes ? `\n**Notes**\n${clip(te.notes, 2000)}` : "",
    te.internalNotes ? `\n**Internal notes**\n${clip(te.internalNotes, 1000)}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function memberLine(m: Member): string {
  const name = [m.firstName, m.lastName].filter(Boolean).join(" ");
  return `- **${m.identifier}** (#${m.id}) — ${name}${m.title ? `, ${m.title}` : ""} · ${m.officeEmail ?? m.defaultEmail ?? ""}${m.inactiveFlag ? " · _inactive_" : ""}`;
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

export function registerTimeTools(server: McpServer): void {
  server.registerTool(
    "cw_search_time_entries",
    {
      title: "Search Time Entries",
      description: `Search time entries across all members/tickets with a conditions filter. Useful for timesheets, utilization, and "what did I log this week".

Condition examples:
  - My time this week: member/identifier="shensger" and timeStart>=[2025-06-02T00:00:00Z] and timeStart<[2025-06-09T00:00:00Z]
  - On a ticket: chargeToType="ServiceTicket" and chargeToId=12345
  - For a company: company/identifier="YELLOWBRICK" and timeStart>=[2025-06-01T00:00:00Z]
  - Unbilled/unapproved: status="Open" or billableOption="Billable"

Returns paged entries with member, start/end, hours, charge-to target, work type, billable option and notes, plus the sum of hours on the page.`,
      inputSchema: {
        ...listFilterSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<TimeEntry>(
        "time/entries",
        {
          conditions: a.conditions,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "timeStart desc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      const sum = paged.items.reduce((s, e) => s + (e.actualHours ?? 0), 0);
      const result = listResult(paged, a.response_format, {
        title: `Time entries${a.conditions ? ` where ${a.conditions}` : ""} — page total ${hours(sum)}`,
        itemKey: "time_entries",
        renderItem: timeEntryLine,
      });
      if (result.structuredContent) result.structuredContent.page_total_hours = sum;
      return result;
    }),
  );

  server.registerTool(
    "cw_get_time_entry",
    {
      title: "Get Time Entry",
      description: `Get one time entry by ID with all fields (member, charge-to, start/end, hours, work type/role, billable option, notes, internal notes).`,
      inputSchema: {
        timeEntryId: z.number().int().positive().describe("Time entry ID"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const te = await cwGet<TimeEntry>(`time/entries/${a.timeEntryId}`);
      return recordResult(te, a.response_format, timeEntryDetail);
    }),
  );

  server.registerTool(
    "cw_create_time_entry",
    {
      title: "Create Time Entry",
      description: `Log time against a service ticket (default), project ticket, activity, or a company (non-ticket time).
Provide time_start and either time_end or actual_hours. Times are ISO 8601 UTC (e.g. 2025-06-05T16:30:00Z) — convert from the member's local time zone first.
The 'notes' text is the time entry description; set add_to_discussion / add_to_internal / add_to_resolution to also append it to the ticket notes. Defaults to the API member unless member_identifier is given.
Work type and work role default to the member's defaults if omitted. Returns the created entry.`,
      inputSchema: {
        charge_to_id: z.number().int().positive().describe("Ticket ID (or activity ID) to charge time to"),
        charge_to_type: z
          .enum(["ServiceTicket", "ProjectTicket", "ChargeCode", "Activity"])
          .default("ServiceTicket")
          .describe("What charge_to_id refers to"),
        time_start: z.string().describe("Start time, ISO 8601 UTC, e.g. 2025-06-05T16:00:00Z"),
        time_end: z.string().optional().describe("End time, ISO 8601 UTC. Provide this or actual_hours."),
        actual_hours: z.number().positive().max(24).optional().describe("Duration in hours (e.g. 0.5). Provide this or time_end."),
        notes: z.string().optional().describe("Time entry notes / work performed"),
        internal_notes: z.string().optional().describe("Internal-only notes"),
        member_id: z.number().int().optional().describe("Member ID to log time for"),
        member_identifier: z.string().optional().describe("Member identifier (login) to log time for, e.g. \"shensger\""),
        company_id: z.number().int().optional().describe("Company ID (required for ChargeCode entries; inferred from ticket otherwise)"),
        work_type_id: z.number().int().optional(),
        work_type_name: z.string().optional().describe("Work type name, e.g. \"Remote\", \"On-Site\""),
        work_role_id: z.number().int().optional(),
        work_role_name: z.string().optional().describe("Work role name, e.g. \"Engineer\""),
        agreement_id: z.number().int().optional().describe("Agreement ID to bill against"),
        billable_option: z.enum(["Billable", "DoNotBill", "NoCharge", "NoDefault"]).optional().describe("Billing treatment (defaults per agreement/work type)"),
        add_to_discussion: z.boolean().default(false).describe("Also add notes to the ticket Discussion (customer-visible)"),
        add_to_internal: z.boolean().default(false).describe("Also add notes to Internal Analysis"),
        add_to_resolution: z.boolean().default(false).describe("Also add notes to Resolution"),
        email_resource: z.boolean().default(false).describe("Email ticket resources"),
        email_contact: z.boolean().default(false).describe("Email ticket contact"),
        email_cc: z.boolean().default(false).describe("Email CC list"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    safe(async (a) => {
      if (!a.time_end && a.actual_hours === undefined) {
        return textResult("Error: provide either time_end or actual_hours.");
      }
      const body: Record<string, unknown> = {
        chargeToId: a.charge_to_id,
        chargeToType: a.charge_to_type,
        timeStart: a.time_start,
        timeEnd: a.time_end,
        actualHours: a.actual_hours,
        notes: a.notes,
        internalNotes: a.internal_notes,
        member: nameRef(a.member_id, a.member_identifier, "identifier"),
        company: a.company_id !== undefined ? { id: a.company_id } : undefined,
        workType: nameRef(a.work_type_id, a.work_type_name),
        workRole: nameRef(a.work_role_id, a.work_role_name),
        agreement: a.agreement_id !== undefined ? { id: a.agreement_id } : undefined,
        billableOption: a.billable_option,
        addToDetailDescriptionFlag: a.add_to_discussion,
        addToInternalAnalysisFlag: a.add_to_internal,
        addToResolutionFlag: a.add_to_resolution,
        emailResourceFlag: a.email_resource,
        emailContactFlag: a.email_contact,
        emailCcFlag: a.email_cc,
      };
      for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
      const te = await cwPost<TimeEntry>("time/entries", body);
      return recordResult(te, a.response_format, (x) => `Logged ${hours(x.actualHours)} on ${chargeTo(x)} (time entry #${x.id}).\n\n${timeEntryDetail(x)}`);
    }),
  );

  server.registerTool(
    "cw_update_time_entry",
    {
      title: "Update Time Entry",
      description: `Update fields on an existing time entry (JSON Patch). Only fields provided are changed. Entries that are already approved/invoiced may be rejected by ConnectWise.`,
      inputSchema: {
        timeEntryId: z.number().int().positive().describe("Time entry ID"),
        time_start: z.string().optional().describe("ISO 8601 UTC"),
        time_end: z.string().optional().describe("ISO 8601 UTC"),
        actual_hours: z.number().positive().max(24).optional(),
        notes: z.string().optional(),
        internal_notes: z.string().optional(),
        work_type_id: z.number().int().optional(),
        work_type_name: z.string().optional(),
        work_role_id: z.number().int().optional(),
        work_role_name: z.string().optional(),
        billable_option: z.enum(["Billable", "DoNotBill", "NoCharge", "NoDefault"]).optional(),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const ops = toPatchOps({
        timeStart: a.time_start,
        timeEnd: a.time_end,
        actualHours: a.actual_hours,
        notes: a.notes,
        internalNotes: a.internal_notes,
        workType: nameRef(a.work_type_id, a.work_type_name),
        workRole: nameRef(a.work_role_id, a.work_role_name),
        billableOption: a.billable_option,
      });
      if (!ops.length) return textResult("Error: no fields to update were provided.");
      const te = await cwPatch<TimeEntry>(`time/entries/${a.timeEntryId}`, ops);
      return recordResult(te, a.response_format, (x) => `Updated time entry #${x.id}.\n\n${timeEntryDetail(x)}`);
    }),
  );

  server.registerTool(
    "cw_delete_time_entry",
    {
      title: "Delete Time Entry",
      description: `Permanently delete a time entry by ID. Irreversible — confirm the ID with cw_get_time_entry first.`,
      inputSchema: { timeEntryId: z.number().int().positive().describe("Time entry ID") },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      await cwDelete(`time/entries/${a.timeEntryId}`);
      return textResult(`Deleted time entry #${a.timeEntryId}.`);
    }),
  );

  /* ---------------- Reference data ---------------- */

  server.registerTool(
    "cw_list_work_types",
    {
      title: "List Work Types",
      description: `List time-entry work types (e.g. Remote, On-Site, After Hours) with bill-time and rate settings. Active only by default.`,
      inputSchema: { include_inactive: z.boolean().default(false), response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<WorkType>("time/workTypes", { conditions: a.include_inactive ? undefined : "inactiveFlag=false", orderBy: "name asc", pageSize: 200 });
      return listResult(paged, a.response_format, {
        title: "Work types",
        itemKey: "work_types",
        renderItem: (w) => `- **${w.name}** (#${w.id}) · ${w.billTime ?? ""}${w.rateType ? ` · ${w.rateType}` : ""}${w.inactiveFlag ? " · inactive" : ""}`,
      });
    }),
  );

  server.registerTool(
    "cw_list_work_roles",
    {
      title: "List Work Roles",
      description: `List work roles (e.g. Engineer, Sr. Engineer, Project Manager) used on time entries. Active only by default.`,
      inputSchema: { include_inactive: z.boolean().default(false), response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<WorkRole>("time/workRoles", { conditions: a.include_inactive ? undefined : "inactiveFlag=false", orderBy: "name asc", pageSize: 200 });
      return listResult(paged, a.response_format, {
        title: "Work roles",
        itemKey: "work_roles",
        renderItem: (w) => `- **${w.name}** (#${w.id})${w.inactiveFlag ? " · inactive" : ""}`,
      });
    }),
  );

  server.registerTool(
    "cw_search_members",
    {
      title: "Search Members",
      description: `Search ConnectWise members (technicians/users) by identifier, name or email. Member identifiers are used as ticket owners, resources and time-entry members.
Examples: conditions=identifier="shensger" · lastName like "Hens%" · officeEmail contains "netrique". Active only by default.`,
      inputSchema: {
        conditions: z.string().optional().describe(`Filter, e.g. identifier="shensger" or firstName like "Sha%"`),
        include_inactive: z.boolean().default(false),
        ...paginationSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const conds = [a.include_inactive ? undefined : "inactiveFlag=false", a.conditions].filter(Boolean).join(" and ");
      const paged = await cwList<Member>("system/members", { conditions: conds || undefined, orderBy: "identifier asc", page: a.page, pageSize: a.pageSize });
      return listResult(paged, a.response_format, { title: "Members", itemKey: "members", renderItem: memberLine });
    }),
  );

  server.registerTool(
    "cw_get_member",
    {
      title: "Get Member",
      description: `Get one member by numeric ID, including default work role/type, location, department and time zone.`,
      inputSchema: { memberId: z.number().int().positive().describe("Member ID"), response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const m = await cwGet<Member>(`system/members/${a.memberId}`);
      return recordResult(m, a.response_format, (x) =>
        [
          `# Member ${x.identifier} (#${x.id})`,
          kv([
            ["Name", [x.firstName, x.lastName].filter(Boolean).join(" ")],
            ["Title", x.title],
            ["Email", x.officeEmail ?? x.defaultEmail],
            ["Office phone", x.officePhone],
            ["Mobile", x.mobilePhone],
            ["License", x.licenseClass],
            ["Default location", ref(x.defaultLocation)],
            ["Default department", ref(x.defaultDepartment)],
            ["Default work role", ref(x.workRole)],
            ["Default work type", ref(x.workType)],
            ["Time zone", ref(x.timeZone)],
            ["Inactive", x.inactiveFlag ? "yes" : undefined],
          ]),
        ].join("\n"),
      );
    }),
  );

  server.registerTool(
    "cw_get_system_info",
    {
      title: "Get ConnectWise System Info",
      description: `Return ConnectWise Manage version, cloud/on-prem flag and server time zone. Handy as a connectivity/credentials test.`,
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async () => {
      const info = await cwGet<SystemInfo>("system/info");
      return textResult(
        `ConnectWise Manage ${info.version ?? "?"} · ${info.isCloud ? "cloud" : "on-prem"}${info.cloudRegion ? ` (${info.cloudRegion})` : ""} · server TZ ${info.serverTimeZone ?? "?"}`,
        info as unknown as Record<string, unknown>,
      );
    }),
  );
}
