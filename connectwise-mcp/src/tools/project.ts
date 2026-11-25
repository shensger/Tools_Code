/**
 * Project module tools: projects, phases, project tickets and project ticket notes.
 * Log time on project tickets with cw_create_time_entry (charge_to_type="ProjectTicket").
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { cwGet, cwList, cwPost } from "../services/client.js";
import {
  clip,
  hours,
  kv,
  listFilterSchema,
  listResult,
  paginationSchema,
  recordResult,
  ref,
  responseFormatSchema,
  safe,
  when,
} from "../services/format.js";
import type { CwInfo, CwRef, TicketNote } from "../types.js";

interface Project {
  id: number;
  name: string;
  company?: CwRef;
  contact?: CwRef;
  manager?: CwRef;
  board?: CwRef;
  status?: CwRef;
  type?: CwRef;
  billingMethod?: string;
  estimatedStart?: string;
  estimatedEnd?: string;
  actualStart?: string;
  actualEnd?: string;
  budgetHours?: number;
  actualHours?: number;
  percentComplete?: number;
  closedFlag?: boolean;
  agreement?: CwRef;
  description?: string;
  _info?: CwInfo;
}

interface ProjectPhase {
  id: number;
  projectId?: number;
  description?: string;
  wbsCode?: string;
  status?: CwRef;
  parentPhase?: CwRef;
  scheduledStart?: string;
  scheduledEnd?: string;
  budgetHours?: number;
  actualHours?: number;
  _info?: CwInfo;
}

interface ProjectTicket {
  id: number;
  summary: string;
  project?: CwRef;
  phase?: CwRef;
  wbsCode?: string;
  company?: CwRef;
  status?: CwRef;
  owner?: CwRef;
  resources?: string;
  budgetHours?: number;
  actualHours?: number;
  closedFlag?: boolean;
  requiredDate?: string;
  _info?: CwInfo;
}

function projectLine(p: Project): string {
  return `- **#${p.id}** ${p.name} · ${p.company?.name ?? "?"} · ${p.status?.name ?? "?"} · PM ${p.manager?.identifier ?? p.manager?.name ?? "?"} · ${hours(p.actualHours)}/${hours(p.budgetHours)}${p.percentComplete !== undefined ? ` · ${Math.round(p.percentComplete * (p.percentComplete <= 1 ? 100 : 1))}%` : ""}${p.closedFlag ? " · _closed_" : ""}`;
}

function projectDetail(p: Project): string {
  return [
    `# Project #${p.id}: ${p.name}`,
    kv([
      ["Company", ref(p.company)],
      ["Contact", ref(p.contact)],
      ["Manager", ref(p.manager)],
      ["Board", ref(p.board)],
      ["Status", ref(p.status)],
      ["Type", ref(p.type)],
      ["Billing method", p.billingMethod],
      ["Agreement", p.agreement ? ref(p.agreement) : undefined],
      ["Estimated", `${when(p.estimatedStart)} → ${when(p.estimatedEnd)}`],
      ["Actual", p.actualStart ? `${when(p.actualStart)} → ${when(p.actualEnd)}` : undefined],
      ["Hours (actual / budget)", `${hours(p.actualHours)} / ${hours(p.budgetHours)}`],
      ["Closed", p.closedFlag ? "yes" : undefined],
    ]),
    p.description ? `\n**Description**\n${clip(p.description, 2000)}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function phaseLine(ph: ProjectPhase): string {
  return `- **#${ph.id}** ${ph.wbsCode ? `${ph.wbsCode} ` : ""}${ph.description ?? ""} · ${ph.status?.name ?? ""} · ${hours(ph.actualHours)}/${hours(ph.budgetHours)}${ph.scheduledStart ? ` · ${when(ph.scheduledStart).slice(0, 10)} → ${when(ph.scheduledEnd).slice(0, 10)}` : ""}`;
}

function projectTicketLine(t: ProjectTicket): string {
  return `- **#${t.id}** ${t.wbsCode ? `${t.wbsCode} ` : ""}${t.summary} · ${t.project?.name ?? "?"} / ${t.phase?.name ?? "?"} · ${t.status?.name ?? "?"} · ${t.resources ?? t.owner?.identifier ?? ""} · ${hours(t.actualHours)}/${hours(t.budgetHours)}${t.closedFlag ? " · _closed_" : ""}`;
}

function projectTicketDetail(t: ProjectTicket): string {
  return [
    `# Project ticket #${t.id}: ${t.summary}`,
    kv([
      ["Project", ref(t.project)],
      ["Phase", ref(t.phase)],
      ["WBS", t.wbsCode],
      ["Company", ref(t.company)],
      ["Status", ref(t.status)],
      ["Owner", ref(t.owner)],
      ["Resources", t.resources],
      ["Hours (actual / budget)", `${hours(t.actualHours)} / ${hours(t.budgetHours)}`],
      ["Due", t.requiredDate ? when(t.requiredDate) : undefined],
      ["Closed", t.closedFlag ? "yes" : undefined],
    ]),
  ].join("\n");
}

export function registerProjectTools(server: McpServer): void {
  server.registerTool(
    "cw_search_projects",
    {
      title: "Search Projects",
      description: `Search projects.

Condition examples:
  - Open projects for a client: company/identifier="YELLOWBRICK" and closedFlag=false
  - My projects: manager/identifier="shensger" and closedFlag=false
  - By status: status/name="In Progress"`,
      inputSchema: { ...listFilterSchema, response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<Project>(
        "project/projects",
        {
          conditions: a.conditions,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "id desc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      return listResult(paged, a.response_format, {
        title: `Projects${a.conditions ? ` where ${a.conditions}` : ""}`,
        itemKey: "projects",
        renderItem: projectLine,
      });
    }),
  );

  server.registerTool(
    "cw_get_project",
    {
      title: "Get Project",
      description: `Get one project by ID (company, manager, status, billing method, dates, budget vs actual hours), optionally with its phases.`,
      inputSchema: {
        projectId: z.number().int().positive(),
        include_phases: z.boolean().default(true).describe("Also list the project's phases"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const p = await cwGet<Project>(`project/projects/${a.projectId}`);
      let phases: ProjectPhase[] = [];
      if (a.include_phases) {
        const paged = await cwList<ProjectPhase>(`project/projects/${a.projectId}/phases`, { pageSize: 200, orderBy: "wbsCode asc" });
        phases = paged.items;
      }
      const record = { ...p, phases } as Project & { phases: ProjectPhase[] };
      return recordResult(record, a.response_format, (r) =>
        [projectDetail(r), r.phases.length ? `\n## Phases\n${r.phases.map(phaseLine).join("\n")}` : ""].filter(Boolean).join("\n"),
      );
    }),
  );

  server.registerTool(
    "cw_search_project_tickets",
    {
      title: "Search Project Tickets",
      description: `Search project tickets (tasks within project phases).

Condition examples:
  - All tickets on a project: project/id=123
  - Open ones assigned to me: resources contains "shensger" and closedFlag=false
  - In a phase: phase/id=456`,
      inputSchema: { ...listFilterSchema, response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<ProjectTicket>(
        "project/tickets",
        {
          conditions: a.conditions,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "wbsCode asc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      return listResult(paged, a.response_format, {
        title: `Project tickets${a.conditions ? ` where ${a.conditions}` : ""}`,
        itemKey: "project_tickets",
        renderItem: projectTicketLine,
      });
    }),
  );

  server.registerTool(
    "cw_get_project_ticket",
    {
      title: "Get Project Ticket",
      description: `Get one project ticket by ID, optionally with its notes.`,
      inputSchema: {
        ticketId: z.number().int().positive(),
        include_notes: z.boolean().default(false),
        ...paginationSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const t = await cwGet<ProjectTicket>(`project/tickets/${a.ticketId}`);
      let notes: TicketNote[] = [];
      if (a.include_notes) {
        const paged = await cwList<TicketNote>(`project/tickets/${a.ticketId}/notes`, { page: a.page, pageSize: a.pageSize, orderBy: "id desc" });
        notes = paged.items;
      }
      const record = { ...t, notes } as ProjectTicket & { notes: TicketNote[] };
      return recordResult(record, a.response_format, (r) =>
        [
          projectTicketDetail(r),
          r.notes.length
            ? `\n## Notes\n${r.notes.map((n) => `- **#${n.id}** ${when(n.dateCreated)} ${n.createdBy ?? ""}${n.internalAnalysisFlag ? " · internal" : ""}${n.resolutionFlag ? " · resolution" : ""}\n  ${clip(n.text, 500)}`).join("\n")}`
            : "",
        ]
          .filter(Boolean)
          .join("\n"),
      );
    }),
  );

  server.registerTool(
    "cw_add_project_ticket_note",
    {
      title: "Add Project Ticket Note",
      description: `Add a note to a project ticket. Choose where it lands: discussion (customer-visible), internal, and/or resolution.`,
      inputSchema: {
        ticketId: z.number().int().positive(),
        text: z.string().min(1),
        discussion: z.boolean().default(false).describe("Detail description / Discussion (customer-visible)"),
        internal: z.boolean().default(true).describe("Internal analysis"),
        resolution: z.boolean().default(false).describe("Resolution"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    safe(async (a) => {
      const note = await cwPost<TicketNote>(`project/tickets/${a.ticketId}/notes`, {
        text: a.text,
        detailDescriptionFlag: a.discussion,
        internalAnalysisFlag: a.internal,
        resolutionFlag: a.resolution,
      });
      return recordResult(note, a.response_format, (n) => `Added note #${n.id} to project ticket #${a.ticketId}.`);
    }),
  );
}
