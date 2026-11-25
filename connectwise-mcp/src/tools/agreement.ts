/**
 * Finance module tools (read-only): agreements and agreement additions.
 * Use these to check whether a client's work is covered (block hours, managed services, etc.)
 * before logging time or quoting.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { cwGet, cwList } from "../services/client.js";
import {
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
import type { CwInfo, CwRef } from "../types.js";

interface Agreement {
  id: number;
  name: string;
  type?: CwRef;
  company?: CwRef;
  contact?: CwRef;
  site?: CwRef;
  agreementStatus?: string;
  startDate?: string;
  endDate?: string;
  noEndingDateFlag?: boolean;
  cancelledFlag?: boolean;
  dateCancelled?: string;
  reasonCancelled?: string;
  billAmount?: number;
  billingCycle?: CwRef;
  applicationUnits?: string;
  applicationLimit?: number;
  applicationCycle?: string;
  applicationUnlimitedFlag?: boolean;
  oneTimeFlag?: boolean;
  coverAgreementTime?: boolean;
  coverAgreementProduct?: boolean;
  coverAgreementExpense?: boolean;
  workRole?: CwRef;
  workType?: CwRef;
  billTime?: string;
  billExpenses?: string;
  billProducts?: string;
  parentAgreement?: CwRef;
  internalNotes?: string;
  customerPO?: string;
  _info?: CwInfo;
}

interface AgreementAddition {
  id: number;
  product?: CwRef & { identifier?: string };
  quantity?: number;
  lessIncluded?: number;
  unitPrice?: number;
  unitCost?: number;
  billCustomer?: string;
  effectiveDate?: string;
  cancelledDate?: string;
  taxableFlag?: boolean;
  description?: string;
  agreementId?: number;
  _info?: CwInfo;
}

function money(v?: number): string | undefined {
  return v === undefined || v === null ? undefined : `$${Number(v).toFixed(2)}`;
}

function agreementLine(a: Agreement): string {
  const state = a.cancelledFlag ? "_cancelled_" : a.agreementStatus ?? "";
  return `- **#${a.id}** ${a.name} · ${a.company?.name ?? "?"} · ${a.type?.name ?? "?"} · ${when(a.startDate).slice(0, 10)} → ${a.noEndingDateFlag ? "no end" : when(a.endDate).slice(0, 10)} · ${state}${a.billAmount ? ` · ${money(a.billAmount)}/${a.billingCycle?.name ?? "cycle"}` : ""}`;
}

function agreementDetail(a: Agreement): string {
  return [
    `# Agreement #${a.id}: ${a.name}`,
    kv([
      ["Company", ref(a.company)],
      ["Contact", ref(a.contact)],
      ["Type", ref(a.type)],
      ["Status", a.cancelledFlag ? `Cancelled ${when(a.dateCancelled)}${a.reasonCancelled ? ` (${a.reasonCancelled})` : ""}` : a.agreementStatus],
      ["Start", when(a.startDate)],
      ["End", a.noEndingDateFlag ? "No ending date" : when(a.endDate)],
      ["Parent agreement", a.parentAgreement ? ref(a.parentAgreement) : undefined],
      ["Bill amount", money(a.billAmount)],
      ["Billing cycle", a.billingCycle?.name],
      [
        "Application",
        a.applicationUnlimitedFlag
          ? `Unlimited ${a.applicationUnits ?? ""}`.trim()
          : a.applicationLimit !== undefined
            ? `${a.applicationUnits === "Hours" ? hours(a.applicationLimit) : a.applicationLimit} ${a.applicationUnits ?? ""} per ${a.applicationCycle ?? "?"}`
            : undefined,
      ],
      ["Covers", [a.coverAgreementTime && "time", a.coverAgreementProduct && "products", a.coverAgreementExpense && "expenses"].filter(Boolean).join(", ")],
      ["Bill time / expenses / products", [a.billTime, a.billExpenses, a.billProducts].some(Boolean) ? `${a.billTime ?? "—"} / ${a.billExpenses ?? "—"} / ${a.billProducts ?? "—"}` : undefined],
      ["Default work type / role", a.workType || a.workRole ? `${ref(a.workType)} / ${ref(a.workRole)}` : undefined],
      ["Customer PO", a.customerPO],
    ]),
    a.internalNotes ? `\n**Internal notes**\n${a.internalNotes}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function additionLine(x: AgreementAddition): string {
  return `- **#${x.id}** ${x.product?.identifier ?? x.product?.name ?? "?"} · qty ${x.quantity ?? "?"}${x.lessIncluded ? ` (less ${x.lessIncluded} incl.)` : ""} · ${money(x.unitPrice) ?? "—"} ea · ${x.billCustomer ?? ""}${x.cancelledDate ? ` · _cancelled ${when(x.cancelledDate).slice(0, 10)}_` : ""}${x.description ? `\n  ${x.description}` : ""}`;
}

export function registerAgreementTools(server: McpServer): void {
  server.registerTool(
    "cw_search_agreements",
    {
      title: "Search Agreements",
      description: `Search client agreements (managed services, block hours, retainers). Read-only.

Condition examples:
  - A client's active agreements: company/identifier="YELLOWBRICK" and cancelledFlag=false
  - By type: type/name="Managed Services"
  - Expiring soon: endDate<[2025-12-31T00:00:00Z] and noEndingDateFlag=false and cancelledFlag=false`,
      inputSchema: { ...listFilterSchema, response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<Agreement>(
        "finance/agreements",
        {
          conditions: a.conditions,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "company/name asc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      return listResult(paged, a.response_format, {
        title: `Agreements${a.conditions ? ` where ${a.conditions}` : ""}`,
        itemKey: "agreements",
        renderItem: agreementLine,
      });
    }),
  );

  server.registerTool(
    "cw_get_agreement",
    {
      title: "Get Agreement",
      description: `Get one agreement by ID: coverage (time/products/expenses), application limits (e.g. block hours per month), billing, dates and status. Read-only.`,
      inputSchema: {
        agreementId: z.number().int().positive(),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const ag = await cwGet<Agreement>(`finance/agreements/${a.agreementId}`);
      return recordResult(ag, a.response_format, agreementDetail);
    }),
  );

  server.registerTool(
    "cw_list_agreement_additions",
    {
      title: "List Agreement Additions",
      description: `List the additions (billed products/services/seats) on an agreement — e.g. per-device or per-user line items. Read-only.`,
      inputSchema: {
        agreementId: z.number().int().positive(),
        include_cancelled: z.boolean().default(false).describe("Include cancelled additions"),
        ...paginationSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<AgreementAddition>(`finance/agreements/${a.agreementId}/additions`, {
        conditions: a.include_cancelled ? undefined : "cancelledDate=null",
        page: a.page,
        pageSize: a.pageSize,
      });
      return listResult(paged, a.response_format, {
        title: `Additions on agreement #${a.agreementId}`,
        itemKey: "additions",
        renderItem: additionLine,
      });
    }),
  );
}
