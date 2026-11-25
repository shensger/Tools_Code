# connectwise-mcp-server

An MCP (Model Context Protocol) server for **ConnectWise Manage (PSA)**. Lets Claude Desktop, Claude Code, or any MCP client search and work tickets, log time, and look up companies, contacts and configurations through the ConnectWise REST API.

- **49 tools** across Service, Time, Company, Schedule, Agreement and Project modules
- TypeScript, official `@modelcontextprotocol/sdk`, Zod-validated inputs
- Runs locally over **stdio** (default) or as a local **streamable HTTP** server
- Markdown output by default; `response_format: "json"` for raw API fields
- Every list tool supports ConnectWise `conditions` / `orderBy` / `fields` / paging

## Tools

| Area | Tool | What it does |
|---|---|---|
| Service | `cw_search_tickets` | Search tickets with conditions (board, status, owner, company, keyword, dates) |
| | `cw_get_ticket` | Full ticket detail incl. SLA dates, hours, custom fields |
| | `cw_create_ticket` | Create a ticket (board/company by id or name, initial description, priority, type…) |
| | `cw_update_ticket` | Patch status, owner, priority, board, type/subtype/item, summary, resources… |
| | `cw_list_ticket_notes` / `cw_add_ticket_note` | Read the conversation; post Discussion / Internal / Resolution notes |
| | `cw_list_ticket_time_entries` | Time logged on a ticket with page total |
| | `cw_list_ticket_configurations` / `cw_attach_…` / `cw_detach_…` | Assets attached to a ticket |
| | `cw_list_boards`, `cw_list_board_statuses`, `cw_list_board_types`, `cw_list_priorities` | Reference data for valid names/IDs |
| Time | `cw_search_time_entries` | Timesheet queries (member, week, company, ticket) with hour totals |
| | `cw_get_time_entry`, `cw_create_time_entry`, `cw_update_time_entry`, `cw_delete_time_entry` | Manage entries; create supports `time_end` or `actual_hours`, add-to-notes flags, email flags |
| | `cw_list_work_types`, `cw_list_work_roles` | Reference data |
| | `cw_search_members`, `cw_get_member` | Technician lookup (identifier → id, defaults) |
| | `cw_get_system_info` | Version / region — a quick credentials test |
| Company | `cw_search_companies`, `cw_get_company`, `cw_list_company_sites` | Client lookup by name/identifier |
| | `cw_search_contacts`, `cw_get_contact`, `cw_create_contact` | Contacts incl. email/phone communication items |
| | `cw_search_configurations`, `cw_get_configuration`, `cw_create_configuration`, `cw_update_configuration`, `cw_list_configuration_types` | Assets: firewalls, switches, servers, workstations… |
| Schedule | `cw_search_schedule_entries`, `cw_get_schedule_entry` | Dispatch calendar: who is booked when, bookings on a ticket |
| | `cw_create_schedule_entry`, `cw_update_schedule_entry`, `cw_delete_schedule_entry` | Book a tech on a ticket/activity, reschedule, reassign, mark done, remove. A booking is not logged time |
| | `cw_list_schedule_types` | Schedule types (S service, P project, C sales…) and statuses (Firm, Tentative) |
| Agreements | `cw_search_agreements`, `cw_get_agreement`, `cw_list_agreement_additions` | Read-only: coverage, block-hour limits, billing, line items — check before logging time |
| Projects | `cw_search_projects`, `cw_get_project` | Projects with PM, status, budget vs actual hours, phases |
| | `cw_search_project_tickets`, `cw_get_project_ticket`, `cw_add_project_ticket_note` | Project tasks and their notes. Log time with `cw_create_time_entry` (`charge_to_type: "ProjectTicket"`) |

## Setup

### 1. ConnectWise credentials

1. **API member keys** — in ConnectWise Manage: *System → Members → API Members* → create/select an API member with a security role that covers Service, Time, Company, Schedule, Project and Finance (agreements, inquire only) → *API Keys* tab → generate. Save the **public** and **private** key (private shows once).
2. **clientId** — register a free integration at <https://developer.connectwise.com/ClientID> and copy the GUID.
3. **Site** — the API host for your region: `api-na.myconnectwise.net`, `api-eu.myconnectwise.net`, `api-au.myconnectwise.net`, or your on-prem hostname.

### 2. Build

```bash
npm install
npm run build
```

### 3. Claude Desktop

Add to `claude_desktop_config.json` (Windows: `%APPDATA%\Claude\`, macOS: `~/Library/Application Support/Claude/`):

```json
{
  "mcpServers": {
    "connectwise": {
      "command": "node",
      "args": ["C:\\path\\to\\connectwise-mcp-server\\dist\\index.js"],
      "env": {
        "CW_SITE": "api-na.myconnectwise.net",
        "CW_COMPANY_ID": "yourcompanyid",
        "CW_PUBLIC_KEY": "xxxxxxxxxxxxxxxx",
        "CW_PRIVATE_KEY": "xxxxxxxxxxxxxxxx",
        "CW_CLIENT_ID": "00000000-0000-0000-0000-000000000000"
      }
    }
  }
}
```

Restart Claude Desktop, then try: *"What open Help Desk tickets are assigned to me?"* or *"Log 30 minutes on ticket 12345 for reviewing FortiGate logs."*

### Claude Code

```bash
claude mcp add connectwise -e CW_SITE=api-na.myconnectwise.net -e CW_COMPANY_ID=... -e CW_PUBLIC_KEY=... -e CW_PRIVATE_KEY=... -e CW_CLIENT_ID=... -- node /path/to/connectwise-mcp-server/dist/index.js
```

### Environment variables

| Variable | Required | Notes |
|---|---|---|
| `CW_SITE` | yes | API host. `na.myconnectwise.net` is auto-prefixed to `api-na…`. |
| `CW_COMPANY_ID` | yes | Your login company ID |
| `CW_PUBLIC_KEY` / `CW_PRIVATE_KEY` | yes | API member keys |
| `CW_CLIENT_ID` | yes | Developer clientId GUID |
| `CW_CODEBASE` | no | Default `v4_6_release`. Older on-prem may need e.g. `v2020_3` |
| `CW_API_VERSION` | no | Accept-header version, default `2025.1` |
| `TRANSPORT` | no | `stdio` (default) or `http` |
| `PORT` | no | HTTP port (default 3000, binds 127.0.0.1 only) |

## Conditions cheat-sheet

ConnectWise filters use its own expression syntax, passed via the `conditions` parameter:

```
closedFlag=false and board/name="Help Desk"
owner/identifier="shensger" and status/name in ("New","In Progress")
company/identifier="YELLOWBRICK" and dateEntered>[2025-06-01T00:00:00Z]
summary like "%VPN%"
_info/lastUpdated>[2025-06-01T00:00:00Z]
```

Operators: `= != < <= > >= contains like in not`. Strings in double quotes, dates in `[brackets]`, nested fields with `/`. `childConditions` filters sub-collections (`types/name="Client"`), `customFieldConditions` filters custom fields (`caption="Region" and value="West"`).

## Development

```bash
npm run dev          # tsx watch
npm run build
node test/smoke.mjs  # end-to-end test against the bundled mock CW API (no creds needed)
npm run inspect      # MCP Inspector UI
```

`test/mock-cw.mjs` is a tiny fake ConnectWise API; point the server at it with `CW_SITE=http://127.0.0.1:8787` (http is only honoured for local testing — real sites always use https).

## Notes & limits

- Times are ISO 8601 **UTC**. Convert from the technician's local zone before logging time.
- Ticket `summary` is capped at 100 characters by ConnectWise.
- Write tools are marked with MCP annotations (`destructiveHint` on delete/detach) so clients can prompt before running them.
- Responses over 25 000 characters are truncated with a hint to narrow `conditions`, lower `pageSize`, or use `fields`.
- HTTP 429 (rate limit, ~60 requests/min per API member) is retried automatically up to 3 times, honoring `Retry-After`.
- Agreements are read-only on purpose. Not yet covered: invoicing, sales opportunities, product catalog, procurement. The client (`src/services/client.ts`) is generic — adding a tool is one `registerTool` call.

## License

MIT
