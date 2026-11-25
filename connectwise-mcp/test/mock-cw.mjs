// Minimal fake ConnectWise Manage API for local smoke tests (no real credentials needed).
// Usage: node test/mock-cw.mjs   -> listens on http://127.0.0.1:8787
import { createServer } from "node:http";

const tickets = [
  { id: 101, summary: "VPN drops for Zurich users", status: { id: 1, name: "New" }, board: { id: 1, name: "Help Desk" }, company: { id: 7, identifier: "YELLOWBRICK", name: "YellowBrick Data" }, priority: { id: 3, name: "Priority 3 - Normal" }, owner: { id: 9, identifier: "shensger" }, closedFlag: false, dateEntered: "2025-06-01T14:00:00Z", actualHours: 1.5, budgetHours: 4, _info: { lastUpdated: "2025-06-02T10:00:00Z", updatedBy: "shensger" } },
  { id: 102, summary: "FortiGate firmware upgrade SLC", status: { id: 2, name: "In Progress" }, board: { id: 1, name: "Help Desk" }, company: { id: 7, identifier: "YELLOWBRICK", name: "YellowBrick Data" }, priority: { id: 2, name: "Priority 2 - High" }, closedFlag: false, dateEntered: "2025-06-03T09:30:00Z" },
];
const notes = { 101: [{ id: 5001, ticketId: 101, text: "User reports VPN disconnects every ~10 min.", detailDescriptionFlag: true, member: { id: 9, identifier: "shensger" }, dateCreated: "2025-06-01T14:05:00Z" }] };
const timeEntries = [{ id: 9001, chargeToId: 101, chargeToType: "ServiceTicket", member: { id: 9, identifier: "shensger" }, timeStart: "2025-06-01T15:00:00Z", timeEnd: "2025-06-01T16:30:00Z", actualHours: 1.5, workType: { id: 1, name: "Remote" }, billableOption: "Billable", notes: "Reviewed FortiGate logs", company: { id: 7, name: "YellowBrick Data" } }];
const companies = [{ id: 7, identifier: "YELLOWBRICK", name: "YellowBrick Data", status: { id: 1, name: "Active" }, city: "Chicago", state: "IL", phoneNumber: "312-555-0100", deletedFlag: false, types: [{ id: 1, name: "Client" }] }];
const configs = [{ id: 301, name: "CHI-FW01", type: { id: 4, name: "Firewall" }, status: { id: 2, name: "Active" }, company: { id: 7, name: "YellowBrick Data" }, serialNumber: "FGT60FTK1", ipAddress: "10.10.7.1", osInfo: "FortiOS 7.4.4" }];

let nextId = 10000;
const json = (res, code, body, headers = {}) => {
  res.writeHead(code, { "Content-Type": "application/json", ...headers });
  res.end(body === undefined ? "" : JSON.stringify(body));
};

createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname.replace("/v4_6_release/apis/3.0/", "");
  const auth = req.headers.authorization ?? "";
  if (!auth.startsWith("Basic ") || !req.headers.clientid) return json(res, 401, { code: "Unauthorized", message: "Missing auth or clientId" });
  let body = "";
  for await (const c of req) body += c;
  const data = body ? JSON.parse(body) : undefined;
  const q = Object.fromEntries(url.searchParams);
  console.error(`${req.method} ${p} ${JSON.stringify(q)} ${body}`);

  let m;
  if (p === "system/info") return json(res, 200, { version: "v2025.1.12345", isCloud: true, serverTimeZone: "Central Standard Time", cloudRegion: "NA" });
  if (p === "service/tickets" && req.method === "GET") return json(res, 200, tickets, { Link: '<...page=2>; rel="next"' });
  if (p === "service/tickets/count") return json(res, 200, { count: 57 });
  if (p === "service/tickets" && req.method === "POST") { const t = { id: ++nextId, closedFlag: false, dateEntered: new Date().toISOString(), status: { id: 1, name: "New" }, ...data }; tickets.push(t); return json(res, 201, t); }
  if ((m = p.match(/^service\/tickets\/(\d+)$/))) {
    const t = tickets.find((x) => x.id === +m[1]);
    if (!t) return json(res, 404, { code: "NotFound", message: `Ticket ${m[1]} not found` });
    if (req.method === "PATCH") { for (const op of data) t[op.path.slice(1)] = typeof op.value === "object" && op.value.name && !op.value.id ? { id: 99, ...op.value } : op.value; }
    return json(res, 200, t);
  }
  if ((m = p.match(/^service\/tickets\/(\d+)\/notes$/))) {
    if (req.method === "POST") { const n = { id: ++nextId, ticketId: +m[1], dateCreated: new Date().toISOString(), member: { id: 9, identifier: "api" }, ...data }; (notes[m[1]] ??= []).push(n); return json(res, 201, n); }
    return json(res, 200, notes[m[1]] ?? []);
  }
  if (p === "time/entries" && req.method === "GET") return json(res, 200, timeEntries);
  if (p === "time/entries/count") return json(res, 200, { count: timeEntries.length });
  if (p === "time/entries" && req.method === "POST") {
    if (!data.timeEnd && !data.actualHours) return json(res, 400, { code: "InvalidObject", message: "Invalid time entry", errors: [{ field: "timeEnd", message: "Time end or actual hours is required" }] });
    const te = { id: ++nextId, actualHours: data.actualHours ?? (new Date(data.timeEnd) - new Date(data.timeStart)) / 36e5, company: { id: 7, name: "YellowBrick Data" }, member: { id: 9, identifier: "shensger" }, ...data };
    timeEntries.push(te); return json(res, 201, te);
  }
  if (p === "service/boards") return json(res, 200, [{ id: 1, name: "Help Desk" }, { id: 2, name: "Projects", projectFlag: true }]);
  if (p === "service/boards/1/statuses") return json(res, 200, [{ id: 1, name: "New", defaultFlag: true, sortOrder: 1 }, { id: 2, name: "In Progress", sortOrder: 2 }, { id: 3, name: "Completed", closedStatus: true, sortOrder: 9 }]);
  if (p === "service/priorities") return json(res, 200, [{ id: 1, name: "Priority 1 - Emergency" }, { id: 2, name: "Priority 2 - High" }, { id: 3, name: "Priority 3 - Normal", defaultFlag: true }]);
  if (p === "company/companies") return json(res, 200, companies);
  if (p === "company/companies/count") return json(res, 200, { count: 1 });
  if (p === "company/companies/7") return json(res, 200, companies[0]);
  if (p === "company/configurations") return json(res, 200, configs);
  if (p === "company/configurations/count") return json(res, 200, { count: 1 });
  if (p === "company/configurations/301") return json(res, 200, configs[0]);
  if (p === "system/members") return json(res, 200, [{ id: 9, identifier: "shensger", firstName: "Shawn", lastName: "Hensger", officeEmail: "shensger@netrique.com" }]);
  return json(res, 404, { code: "NotFound", message: `No route for ${req.method} ${p}` });
}).listen(8787, "127.0.0.1", () => console.error("mock CW on http://127.0.0.1:8787"));
