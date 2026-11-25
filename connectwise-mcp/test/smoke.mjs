// End-to-end smoke test: starts the mock CW API, launches the MCP server over stdio,
// lists tools and exercises a representative set of calls.
// Usage: npm run build && node test/smoke.mjs
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const mock = spawn(process.execPath, ["test/mock-cw.mjs"], { stdio: ["ignore", "ignore", "inherit"] });
await new Promise((r) => setTimeout(r, 400));

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/index.js"],
  env: {
    ...process.env,
    CW_SITE: "http://127.0.0.1:8787",
    CW_COMPANY_ID: "netrique",
    CW_PUBLIC_KEY: "pub",
    CW_PRIVATE_KEY: "priv",
    CW_CLIENT_ID: "00000000-0000-0000-0000-000000000000",
  },
});
const client = new Client({ name: "smoke", version: "0.0.0" });
let failures = 0;

try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  console.log(`✔ ${tools.length} tools registered:\n  ${tools.map((t) => t.name).join(", ")}\n`);

  const call = async (name, args, expect) => {
    const r = await client.callTool({ name, arguments: args });
    const text = r.content?.[0]?.text ?? "";
    const ok = (expect ? expect(text, r) : !r.isError) === true;
    if (!ok) failures++;
    console.log(`${ok ? "✔" : "✘"} ${name} ${JSON.stringify(args)}\n${text.split("\n").slice(0, 6).map((l) => "    " + l).join("\n")}\n`);
  };

  await call("cw_get_system_info", {});
  await call("cw_search_tickets", { conditions: 'closedFlag=false and board/name="Help Desk"' }, (t) => t.includes("#101") && t.includes("57") && t.includes("page 2"));
  await call("cw_search_tickets", { conditions: "closedFlag=false", response_format: "json" }, (t, r) => r.structuredContent?.tickets?.length === 2 && r.structuredContent.has_more === true);
  await call("cw_get_ticket", { ticketId: 101 }, (t) => t.includes("VPN drops") && t.includes("Budget / Actual hours"));
  await call("cw_get_ticket", { ticketId: 999 }, (t, r) => r.isError === true && t.includes("404"));
  await call("cw_list_ticket_notes", { ticketId: 101 }, (t) => t.includes("Discussion") && t.includes("disconnects"));
  await call("cw_add_ticket_note", { ticketId: 101, text: "Checked FortiGate SSL-VPN timers.", internal: true }, (t) => t.includes("Added Internal note"));
  await call("cw_create_ticket", { summary: "Test ticket", board_name: "Help Desk", company_identifier: "YELLOWBRICK", initial_description: "hello", priority_name: "Priority 3 - Normal" }, (t) => t.includes("Created ticket #"));
  await call("cw_create_ticket", { summary: "Missing board", company_identifier: "YELLOWBRICK" }, (t) => t.includes("board_id or board_name"));
  await call("cw_update_ticket", { ticketId: 102, status_name: "Completed", owner_identifier: "shensger" }, (t) => t.includes("Updated ticket #102") && t.includes("Completed"));
  await call("cw_list_ticket_time_entries", { ticketId: 101 }, (t) => t.includes("1.50h"));
  await call("cw_create_time_entry", { charge_to_id: 101, time_start: "2025-06-05T16:00:00Z", time_end: "2025-06-05T16:45:00Z", notes: "Applied fix", work_type_name: "Remote" }, (t) => t.includes("Logged 0.75h"));
  await call("cw_create_time_entry", { charge_to_id: 101, time_start: "2025-06-05T16:00:00Z" }, (t) => t.includes("time_end or actual_hours"));
  await call("cw_search_time_entries", { conditions: 'member/identifier="shensger"' }, (t) => t.includes("page total"));
  await call("cw_list_boards", {}, (t) => t.includes("Help Desk"));
  await call("cw_list_board_statuses", { boardId: 1 }, (t) => t.includes("Completed") && t.includes("closed"));
  await call("cw_list_priorities", {}, (t) => t.includes("Emergency"));
  await call("cw_search_companies", { conditions: 'name like "%Yellow%"' }, (t) => t.includes("YELLOWBRICK"));
  await call("cw_get_company", { company_identifier: "YELLOWBRICK" }, (t) => t.includes("Chicago"));
  await call("cw_search_configurations", { conditions: 'type/name="Firewall"' }, (t) => t.includes("CHI-FW01") && t.includes("10.10.7.1"));
  await call("cw_get_configuration", { configurationId: 301 }, (t) => t.includes("FortiOS"));
  await call("cw_search_members", { conditions: 'identifier="shensger"' }, (t) => t.includes("Shawn Hensger"));
} finally {
  await client.close().catch(() => {});
  mock.kill();
}

console.log(failures ? `\n${failures} check(s) FAILED` : "\nAll checks passed");
process.exit(failures ? 1 : 0);
