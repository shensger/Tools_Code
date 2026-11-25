/**
 * Company module tools: companies, contacts, sites, configurations (assets).
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { cwGet, cwList, cwPatch, cwPost, toPatchOps } from "../services/client.js";
import {
  clip,
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
import type { Company, CompanySite, Configuration, ConfigurationType, Contact } from "../types.js";

/* ------------------------------------------------------------------ */
/* Renderers                                                           */
/* ------------------------------------------------------------------ */

function address(x: { addressLine1?: string; addressLine2?: string; city?: string; state?: string; zip?: string }): string {
  return [x.addressLine1, x.addressLine2, [x.city, x.state].filter(Boolean).join(", "), x.zip].filter(Boolean).join(", ");
}

function companyLine(c: Company): string {
  return `- **${c.name}** (${c.identifier}, #${c.id}) — ${c.status?.name ?? "?"} · ${[c.city, c.state].filter(Boolean).join(", ")}${c.phoneNumber ? ` · ${c.phoneNumber}` : ""}${c.types?.length ? ` · ${c.types.map((t) => t.name).join("/")}` : ""}`;
}

function companyDetail(c: Company): string {
  return [
    `# ${c.name} (${c.identifier}, #${c.id})`,
    kv([
      ["Status", ref(c.status)],
      ["Types", c.types?.map((t) => t.name).join(", ")],
      ["Address", address(c)],
      ["Country", c.country?.name],
      ["Phone", c.phoneNumber],
      ["Fax", c.faxNumber],
      ["Website", c.website],
      ["Default contact", ref(c.defaultContact)],
      ["Primary site", ref(c.site)],
      ["Territory", ref(c.territory)],
      ["Market", ref(c.market)],
      ["Account #", c.accountNumber],
      ["Employees", c.numberOfEmployees],
      ["Acquired", when(c.dateAcquired)],
      ["Deleted", c.deletedFlag ? "yes" : undefined],
      ["Last updated", c._info?.lastUpdated ? `${when(c._info.lastUpdated)} by ${c._info.updatedBy ?? "?"}` : undefined],
    ]),
  ].join("\n");
}

function contactComms(ct: Contact): { email?: string; phone?: string; all: string } {
  const items = ct.communicationItems ?? [];
  const email = items.find((i) => i.communicationType === "Email" && i.defaultFlag)?.value ?? items.find((i) => i.communicationType === "Email")?.value;
  const phone = items.find((i) => i.communicationType === "Phone" && i.defaultFlag)?.value ?? items.find((i) => i.communicationType === "Phone")?.value;
  const all = items.map((i) => `${i.type?.name ?? i.communicationType ?? "?"}: ${i.value}${i.defaultFlag ? " (default)" : ""}`).join("; ");
  return { email, phone, all };
}

function contactLine(ct: Contact): string {
  const { email, phone } = contactComms(ct);
  const name = [ct.firstName, ct.lastName].filter(Boolean).join(" ");
  return `- **${name}** (#${ct.id}) — ${ct.company?.name ?? "?"}${ct.title ? ` · ${ct.title}` : ""}${email ? ` · ${email}` : ""}${phone ? ` · ${phone}` : ""}${ct.defaultFlag ? " · default" : ""}${ct.inactiveFlag ? " · _inactive_" : ""}`;
}

function contactDetail(ct: Contact): string {
  const { all } = contactComms(ct);
  return [
    `# ${[ct.firstName, ct.lastName].filter(Boolean).join(" ")} (#${ct.id})`,
    kv([
      ["Company", ref(ct.company)],
      ["Site", ref(ct.site)],
      ["Title", ct.title],
      ["Department", ref(ct.department)],
      ["Types", ct.types?.map((t) => t.name).join(", ")],
      ["Communication", all],
      ["Default contact", ct.defaultFlag ? "yes" : undefined],
      ["Inactive", ct.inactiveFlag ? "yes" : undefined],
    ]),
  ].join("\n");
}

function siteLine(s: CompanySite): string {
  return `- **${s.name}** (#${s.id}) — ${address(s)}${s.phoneNumber ? ` · ${s.phoneNumber}` : ""}${s.primaryAddressFlag ? " · primary" : ""}${s.inactiveFlag ? " · _inactive_" : ""}`;
}

function configLine(c: Configuration): string {
  return `- **${c.name}** (#${c.id}) — ${c.type?.name ?? "?"} · ${c.status?.name ?? ""} · ${c.company?.name ?? ""}${c.serialNumber ? ` · SN ${c.serialNumber}` : ""}${c.ipAddress ? ` · ${c.ipAddress}` : ""}${c.osInfo ? ` · ${clip(c.osInfo, 40)}` : ""}`;
}

function configDetail(c: Configuration): string {
  return [
    `# Configuration: ${c.name} (#${c.id})`,
    kv([
      ["Type", ref(c.type)],
      ["Status", ref(c.status)],
      ["Company", ref(c.company)],
      ["Site", ref(c.site)],
      ["Contact", ref(c.contact)],
      ["Device identifier", c.deviceIdentifier],
      ["Serial number", c.serialNumber],
      ["Model", c.modelNumber],
      ["Tag", c.tagNumber],
      ["Manufacturer", ref(c.manufacturer)],
      ["Vendor", ref(c.vendor)],
      ["IP address", c.ipAddress],
      ["Default gateway", c.defaultGateway],
      ["MAC", c.macAddress],
      ["OS", [c.osType, c.osInfo].filter(Boolean).join(" — ")],
      ["CPU / RAM", [c.cpuSpeed, c.ram].filter(Boolean).join(" / ")],
      ["Drives", c.localHardDrives],
      ["Last login", c.lastLoginName],
      ["Purchased", when(c.purchaseDate)],
      ["Installed", when(c.installationDate)],
      ["Warranty expires", when(c.warrantyExpirationDate)],
      ["Management link", c.managementLink],
      ["Remote link", c.remoteLink],
      ["Active", c.activeFlag === false ? "no" : undefined],
      ["Last updated", c._info?.lastUpdated ? `${when(c._info.lastUpdated)} by ${c._info.updatedBy ?? "?"}` : undefined],
    ]),
    c.notes ? `\n**Notes**\n${clip(c.notes, 1500)}` : "",
    c.questions?.length
      ? `\n**Questions**\n${c.questions.filter((q) => q.answer !== undefined && q.answer !== null && q.answer !== "").map((q) => `- ${q.question}: ${String(q.answer)}`).join("\n")}`
      : "",
  ]
    .filter(Boolean)
    .join("\n");
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

export function registerCompanyTools(server: McpServer): void {
  /* ---------------- Companies ---------------- */

  server.registerTool(
    "cw_search_companies",
    {
      title: "Search Companies",
      description: `Search companies (clients, vendors, prospects) by name, identifier, status or type.
Condition examples: name like "%Yellow%" · identifier="YELLOWBRICK" · status/name="Active" · city="Chicago". Use childConditions=types/name="Client" to filter by company type. Deleted companies excluded by default.
Returns id, identifier, name, status, city/state, phone.`,
      inputSchema: {
        ...listFilterSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const conds = ["deletedFlag=false", a.conditions].filter(Boolean).join(" and ");
      const paged = await cwList<Company>(
        "company/companies",
        {
          conditions: conds,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "name asc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      return listResult(paged, a.response_format, { title: "Companies", itemKey: "companies", renderItem: companyLine });
    }),
  );

  server.registerTool(
    "cw_get_company",
    {
      title: "Get Company",
      description: `Get one company by numeric ID or identifier with address, status, types, default contact, territory and account details.`,
      inputSchema: {
        company_id: z.number().int().positive().optional().describe("Company ID"),
        company_identifier: z.string().optional().describe("Company identifier (alternative to company_id)"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      let c: Company | undefined;
      if (a.company_id !== undefined) {
        c = await cwGet<Company>(`company/companies/${a.company_id}`);
      } else if (a.company_identifier) {
        const list = await cwList<Company>("company/companies", { conditions: `identifier="${a.company_identifier.replace(/"/g, '\\"')}"`, pageSize: 1 });
        c = list.items[0];
        if (!c) return textResult(`No company with identifier "${a.company_identifier}". Try cw_search_companies with name like "%…%".`);
      } else {
        return textResult("Error: provide company_id or company_identifier.");
      }
      return recordResult(c, a.response_format, companyDetail);
    }),
  );

  server.registerTool(
    "cw_list_company_sites",
    {
      title: "List Company Sites",
      description: `List sites (locations/addresses) for a company. Site IDs are used on tickets and configurations.`,
      inputSchema: {
        companyId: z.number().int().positive().describe("Company ID"),
        include_inactive: z.boolean().default(false),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<CompanySite>(`company/companies/${a.companyId}/sites`, {
        conditions: a.include_inactive ? undefined : "inactiveFlag=false",
        orderBy: "name asc",
        pageSize: 200,
      });
      return listResult(paged, a.response_format, { title: `Sites for company #${a.companyId}`, itemKey: "sites", renderItem: siteLine });
    }),
  );

  /* ---------------- Contacts ---------------- */

  server.registerTool(
    "cw_search_contacts",
    {
      title: "Search Contacts",
      description: `Search contacts by name, company or email.
Condition examples: company/identifier="YELLOWBRICK" · lastName like "Smi%" · firstName="Kim". To find by email use childConditions=communicationItems/value="kim@example.com".
Returns name, company, title, default email/phone. Inactive contacts excluded by default.`,
      inputSchema: {
        ...listFilterSchema,
        include_inactive: z.boolean().default(false),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const conds = [a.include_inactive ? undefined : "inactiveFlag=false", a.conditions].filter(Boolean).join(" and ");
      const paged = await cwList<Contact>(
        "company/contacts",
        {
          conditions: conds || undefined,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "lastName asc, firstName asc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      return listResult(paged, a.response_format, { title: "Contacts", itemKey: "contacts", renderItem: contactLine });
    }),
  );

  server.registerTool(
    "cw_get_contact",
    {
      title: "Get Contact",
      description: `Get one contact by ID with all communication items (emails, phones), company, site, title and types.`,
      inputSchema: { contactId: z.number().int().positive().describe("Contact ID"), response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const ct = await cwGet<Contact>(`company/contacts/${a.contactId}`);
      return recordResult(ct, a.response_format, contactDetail);
    }),
  );

  server.registerTool(
    "cw_create_contact",
    {
      title: "Create Contact",
      description: `Create a contact under a company with optional email, phone, title and site. Returns the created contact.`,
      inputSchema: {
        first_name: z.string().min(1).describe("First name"),
        last_name: z.string().optional().describe("Last name"),
        company_id: z.number().int().optional().describe("Company ID"),
        company_identifier: z.string().optional().describe("Company identifier (alternative to company_id)"),
        email: z.string().email().optional().describe("Primary email"),
        phone: z.string().optional().describe("Direct phone"),
        mobile: z.string().optional().describe("Mobile phone"),
        title: z.string().optional(),
        site_id: z.number().int().optional(),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    safe(async (a) => {
      const company = nameRef(a.company_id, a.company_identifier, "identifier");
      if (!company) return textResult("Error: company_id or company_identifier is required.");
      const communicationItems: Array<Record<string, unknown>> = [];
      if (a.email) communicationItems.push({ type: { name: "Email" }, value: a.email, defaultFlag: true, communicationType: "Email" });
      if (a.phone) communicationItems.push({ type: { name: "Direct" }, value: a.phone, defaultFlag: true, communicationType: "Phone" });
      if (a.mobile) communicationItems.push({ type: { name: "Cell" }, value: a.mobile, defaultFlag: !a.phone, communicationType: "Phone" });
      const body: Record<string, unknown> = {
        firstName: a.first_name,
        lastName: a.last_name,
        company,
        title: a.title,
        site: a.site_id !== undefined ? { id: a.site_id } : undefined,
        communicationItems: communicationItems.length ? communicationItems : undefined,
      };
      for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
      const ct = await cwPost<Contact>("company/contacts", body);
      return recordResult(ct, a.response_format, (x) => `Created contact #${x.id}.\n\n${contactDetail(x)}`);
    }),
  );

  /* ---------------- Configurations ---------------- */

  server.registerTool(
    "cw_search_configurations",
    {
      title: "Search Configurations (Assets)",
      description: `Search configurations — managed devices/assets such as servers, switches, firewalls, workstations, licenses.
Condition examples: company/identifier="YELLOWBRICK" and activeFlag=true · name like "%FW%" · type/name="Firewall" · serialNumber="FGT60F..." · ipAddress="10.10.7.13" · status/name="Active".
Returns name, type, status, company, serial, IP, OS.`,
      inputSchema: {
        ...listFilterSchema,
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<Configuration>(
        "company/configurations",
        {
          conditions: a.conditions,
          childConditions: a.childConditions,
          customFieldConditions: a.customFieldConditions,
          orderBy: a.orderBy ?? "name asc",
          fields: a.fields,
          page: a.page,
          pageSize: a.pageSize,
        },
        { includeTotal: true },
      );
      return listResult(paged, a.response_format, { title: "Configurations", itemKey: "configurations", renderItem: configLine });
    }),
  );

  server.registerTool(
    "cw_get_configuration",
    {
      title: "Get Configuration",
      description: `Get one configuration (asset) by ID with hardware, network, OS, warranty, links, notes and question/answer fields.`,
      inputSchema: { configurationId: z.number().int().positive().describe("Configuration ID"), response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const c = await cwGet<Configuration>(`company/configurations/${a.configurationId}`);
      return recordResult(c, a.response_format, configDetail);
    }),
  );

  server.registerTool(
    "cw_create_configuration",
    {
      title: "Create Configuration",
      description: `Create a configuration (asset) for a company. Requires name, type (id or name) and company (id or identifier). Returns the created configuration.`,
      inputSchema: {
        name: z.string().min(1).max(100).describe("Configuration name (e.g. hostname)"),
        type_id: z.number().int().optional().describe("Configuration type ID"),
        type_name: z.string().optional().describe("Configuration type name, e.g. \"Firewall\", \"Server\""),
        company_id: z.number().int().optional(),
        company_identifier: z.string().optional(),
        status_id: z.number().int().optional(),
        status_name: z.string().optional().describe("Configuration status name, e.g. \"Active\""),
        site_id: z.number().int().optional(),
        contact_id: z.number().int().optional(),
        serial_number: z.string().optional(),
        model_number: z.string().optional(),
        tag_number: z.string().optional(),
        manufacturer_name: z.string().optional(),
        ip_address: z.string().optional(),
        default_gateway: z.string().optional(),
        mac_address: z.string().optional(),
        os_type: z.string().optional(),
        os_info: z.string().optional(),
        purchase_date: z.string().optional().describe("ISO 8601"),
        installation_date: z.string().optional().describe("ISO 8601"),
        warranty_expiration_date: z.string().optional().describe("ISO 8601"),
        management_link: z.string().optional(),
        remote_link: z.string().optional(),
        notes: z.string().optional(),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    safe(async (a) => {
      const type = nameRef(a.type_id, a.type_name);
      const company = nameRef(a.company_id, a.company_identifier, "identifier");
      if (!type) return textResult("Error: type_id or type_name is required. Use cw_list_configuration_types.");
      if (!company) return textResult("Error: company_id or company_identifier is required.");
      const body: Record<string, unknown> = {
        name: a.name,
        type,
        company,
        status: nameRef(a.status_id, a.status_name),
        site: a.site_id !== undefined ? { id: a.site_id } : undefined,
        contact: a.contact_id !== undefined ? { id: a.contact_id } : undefined,
        serialNumber: a.serial_number,
        modelNumber: a.model_number,
        tagNumber: a.tag_number,
        manufacturer: a.manufacturer_name ? { name: a.manufacturer_name } : undefined,
        ipAddress: a.ip_address,
        defaultGateway: a.default_gateway,
        macAddress: a.mac_address,
        osType: a.os_type,
        osInfo: a.os_info,
        purchaseDate: a.purchase_date,
        installationDate: a.installation_date,
        warrantyExpirationDate: a.warranty_expiration_date,
        managementLink: a.management_link,
        remoteLink: a.remote_link,
        notes: a.notes,
      };
      for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
      const c = await cwPost<Configuration>("company/configurations", body);
      return recordResult(c, a.response_format, (x) => `Created configuration #${x.id}.\n\n${configDetail(x)}`);
    }),
  );

  server.registerTool(
    "cw_update_configuration",
    {
      title: "Update Configuration",
      description: `Update fields on a configuration (JSON Patch). Only provided fields change. Useful for keeping IPs, serials, OS info, warranty dates and notes current.`,
      inputSchema: {
        configurationId: z.number().int().positive().describe("Configuration ID"),
        name: z.string().min(1).max(100).optional(),
        status_id: z.number().int().optional(),
        status_name: z.string().optional(),
        type_id: z.number().int().optional(),
        type_name: z.string().optional(),
        site_id: z.number().int().optional(),
        contact_id: z.number().int().optional(),
        serial_number: z.string().optional(),
        model_number: z.string().optional(),
        tag_number: z.string().optional(),
        ip_address: z.string().optional(),
        default_gateway: z.string().optional(),
        mac_address: z.string().optional(),
        os_type: z.string().optional(),
        os_info: z.string().optional(),
        purchase_date: z.string().optional(),
        installation_date: z.string().optional(),
        warranty_expiration_date: z.string().optional(),
        management_link: z.string().optional(),
        remote_link: z.string().optional(),
        notes: z.string().optional(),
        active: z.boolean().optional().describe("Set activeFlag"),
        response_format: responseFormatSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const ops = toPatchOps({
        name: a.name,
        status: nameRef(a.status_id, a.status_name),
        type: nameRef(a.type_id, a.type_name),
        site: a.site_id !== undefined ? { id: a.site_id } : undefined,
        contact: a.contact_id !== undefined ? { id: a.contact_id } : undefined,
        serialNumber: a.serial_number,
        modelNumber: a.model_number,
        tagNumber: a.tag_number,
        ipAddress: a.ip_address,
        defaultGateway: a.default_gateway,
        macAddress: a.mac_address,
        osType: a.os_type,
        osInfo: a.os_info,
        purchaseDate: a.purchase_date,
        installationDate: a.installation_date,
        warrantyExpirationDate: a.warranty_expiration_date,
        managementLink: a.management_link,
        remoteLink: a.remote_link,
        notes: a.notes,
        activeFlag: a.active,
      });
      if (!ops.length) return textResult("Error: no fields to update were provided.");
      const c = await cwPatch<Configuration>(`company/configurations/${a.configurationId}`, ops);
      return recordResult(c, a.response_format, (x) => `Updated configuration #${x.id} (${ops.map((o) => o.path.slice(1)).join(", ")}).\n\n${configDetail(x)}`);
    }),
  );

  server.registerTool(
    "cw_list_configuration_types",
    {
      title: "List Configuration Types",
      description: `List configuration types (e.g. Server, Workstation, Firewall, Switch, Managed Router) and their IDs. Active only by default.`,
      inputSchema: { include_inactive: z.boolean().default(false), response_format: responseFormatSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    safe(async (a) => {
      const paged = await cwList<ConfigurationType>("company/configurations/types", {
        conditions: a.include_inactive ? undefined : "inactiveFlag=false",
        orderBy: "name asc",
        pageSize: 200,
      });
      return listResult(paged, a.response_format, {
        title: "Configuration types",
        itemKey: "configuration_types",
        renderItem: (t) => `- **${t.name}** (#${t.id})${t.inactiveFlag ? " · inactive" : ""}`,
      });
    }),
  );
}
