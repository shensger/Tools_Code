# NinjaOne MCP Server

A Model Context Protocol (MCP) server for the NinjaOne RMM platform. Gives AI assistants access to
device management, monitoring, alerts, scripting/actions, patch & software management,
organizations, policies, groups, and ticketing via the NinjaOne REST API v2.

65 tools across 11 domains — see the tables below. Every tool wraps a real, verified NinjaOne
public API endpoint (cross-checked against NinjaOne's published OpenAPI spec); a few tools from
an earlier version of this server called endpoints that don't actually exist (a global script
library, a per-job status lookup, a device-alerts bulk delete) — those have been fixed or
replaced with the real equivalents.

## Setup

> **Full install guide:** [SETUP.md](SETUP.md). **Have Claude install it for an end user:** [CLAUDE_BUILD.md](CLAUDE_BUILD.md).

### 1. Create a NinjaOne API Application

NinjaOne has two different "app" types in Administration > Apps > API — make sure you pick the
machine-to-machine one, not the interactive login one:

1. Log in to your NinjaOne dashboard
2. Go to **Administration > Apps > API**
3. Click **Add** (or **Add client app id**)
4. **Application Platform**: choose **API Services (Machine-to-Machine)** — not Web/Native/SPA
5. **Scopes**: check **Monitoring**, **Management**, and **Control** (Control is required for
   scripts, reboots, and service control — skip it and those tools will fail with a 403)
6. **Allowed Grant Types**: **Client Credentials**
7. **Redirect URI**: leave blank
8. Save — NinjaOne shows a **Client ID** and **Client Secret** once. Copy both now; the secret
   isn't shown again.

### 2. Configure Claude Desktop

Add this to your local MCP server configuration:

```json
{
  "mcpServers": {
    "ninjaone": {
      "command": "node",
      "args": ["/path/to/ninjaone-mcp-server/dist/index.js"],
      "env": {
        "NINJAONE_CLIENT_ID": "your-client-id",
        "NINJAONE_CLIENT_SECRET": "your-client-secret",
        "NINJAONE_REGION": "us"
      }
    }
  }
}
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|--------------|
| `NINJAONE_CLIENT_ID` | Yes | OAuth 2.0 Client ID |
| `NINJAONE_CLIENT_SECRET` | Yes | OAuth 2.0 Client Secret |
| `NINJAONE_REGION` | No | `us` (default), `eu`, or `oc` — NinjaOne has no separate Canada region; Canadian tenants are hosted on `us` or `eu` |

### Build

```bash
npm install
npm run build
```

### Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector node dist/index.js
```

## Tools

### Devices — core

| Tool | Description |
|------|-------------|
| `ninjaone_list_devices` | List devices with filters (org, class, offline status) |
| `ninjaone_list_devices_detailed` | Same, with richer per-device data in one call |
| `ninjaone_search_devices` | Free-text search by name, user, or IP |
| `ninjaone_get_device` | Get full details for a device |
| `ninjaone_get_device_alerts` | Get active alerts on a device |
| `ninjaone_get_device_activities` | Get activity log for a device |
| `ninjaone_get_device_jobs` | List active jobs on a device |
| `ninjaone_reboot_device` | Reboot a device (NORMAL/FORCED) |
| `ninjaone_approve_devices` | Approve/reject pending devices |

### Devices — hardware & software

| Tool | Description |
|------|-------------|
| `ninjaone_get_device_services` | List Windows services on a device |
| `ninjaone_control_windows_service` | Start/stop/pause/restart a Windows service |
| `ninjaone_list_device_disks` | List physical disk drives |
| `ninjaone_list_device_volumes` | List storage volumes (capacity/free space) |
| `ninjaone_list_device_processors` | List CPUs |
| `ninjaone_list_device_software` | List installed software on one device |
| `ninjaone_get_last_logged_on_user` | Get last logged-on username |

### Devices — configuration

| Tool | Description |
|------|-------------|
| `ninjaone_get_device_custom_fields` / `ninjaone_update_device_custom_fields` | Read/write custom field values |
| `ninjaone_set_device_maintenance` / `ninjaone_clear_device_maintenance` | Schedule/end a maintenance window |
| `ninjaone_get_device_policy_overrides` / `ninjaone_clear_device_policy_overrides` | View/reset device-level policy overrides |

### Devices — patch & software management

| Tool | Description |
|------|-------------|
| `ninjaone_get_device_os_patches` | Pending/failed/rejected OS patches for one device |
| `ninjaone_get_device_os_patch_installs` | OS patch install history for one device |
| `ninjaone_get_device_software_patches` | Pending/failed/rejected 3rd-party software patches |
| `ninjaone_get_device_software_patch_installs` | Software patch install history |

### Fleet-wide queries

| Tool | Description |
|------|-------------|
| `ninjaone_query_software` | Software inventory across devices |
| `ninjaone_query_os_patches` / `ninjaone_query_os_patch_installs` | OS patch compliance / install history, fleet-wide |
| `ninjaone_query_software_patches` / `ninjaone_query_software_patch_installs` | Software patch compliance / install history, fleet-wide |
| `ninjaone_query_device_health` | Device health/score report |
| `ninjaone_query_antivirus_status` / `ninjaone_query_antivirus_threats` | AV product status / detected threats |
| `ninjaone_query_operating_systems` | OS versions across the fleet |
| `ninjaone_query_computer_systems` | Hardware/asset details across the fleet |
| `ninjaone_query_logged_on_users` | Who's logged into what, fleet-wide |

*(Patch **installation/approval** itself isn't exposed by NinjaOne's public API — that's configured
through policies in the console, or triggered via a script. These tools cover status/reporting.)*

### Groups

| Tool | Description |
|------|-------------|
| `ninjaone_list_groups` | List saved device groups |
| `ninjaone_list_group_device_ids` | List devices currently matching a group |

### Organizations

| Tool | Description |
|------|-------------|
| `ninjaone_list_organizations` | List organizations |
| `ninjaone_get_organization` | Get organization details |
| `ninjaone_create_organization` / `ninjaone_update_organization` | Create/update an organization |
| `ninjaone_list_organization_locations` / `ninjaone_list_locations` | List locations (per-org / global) |
| `ninjaone_create_organization_location` / `ninjaone_update_organization_location` | Create/update a location |
| `ninjaone_list_organizations_detailed` | Same as list, with fuller per-org payload in one call |

### Policies

| Tool | Description |
|------|-------------|
| `ninjaone_list_policies` | List policies |
| `ninjaone_create_policy` | Create a policy (new / child / copy) |
| `ninjaone_list_roles` | List device roles (needed for policy mapping) |
| `ninjaone_set_organization_policy_mappings` | Set which policy applies to which role in an org |

### Alerts

| Tool | Description |
|------|-------------|
| `ninjaone_list_alerts` | List active alerts with filters |
| `ninjaone_reset_alert` | Reset an alert's condition by UID |
| `ninjaone_delete_alert` | Delete an alert record by UID |
| `ninjaone_reset_device_alerts` | Reset every active alert on a device |

### Scripts & Jobs

| Tool | Description |
|------|-------------|
| `ninjaone_get_device_scripting_options` | List scripts/actions runnable on a device |
| `ninjaone_run_script_or_action` | Run a script or built-in action on a device |
| `ninjaone_list_active_jobs` | List active jobs fleet-wide |

### Tickets

| Tool | Description |
|------|-------------|
| `ninjaone_list_ticket_boards` | List ticket boards |
| `ninjaone_search_tickets` | Search/list tickets on a board |
| `ninjaone_create_ticket` / `ninjaone_update_ticket` | Create/update a ticket (update can add a comment) |
| `ninjaone_get_ticket_log_entries` | Get a ticket's comment/status history |
| `ninjaone_list_ticket_forms` / `ninjaone_list_ticket_contacts` | List ticket forms / contacts |

## API Regions

| Region | Base URL |
|--------|----------|
| `us` | `https://app.ninjarmm.com` |
| `eu` | `https://eu.ninjarmm.com` |
| `oc` | `https://oc.ninjarmm.com` |

## Notes

- Tokens are cached in memory, refreshed ~60s before expiry, and auto-retried once on a 401.
  Fine for a single-process stdio server; a multi-instance HTTP deployment would need a shared
  token cache instead.
- NinjaOne's device filter syntax (`df` parameter, e.g. `"organization = 5 AND class = WINDOWS_SERVER"`)
  is used throughout for scoping fleet-wide queries — pass it as `device_filter` on any tool that
  accepts it.
- Ticketing uses NinjaOne's board-based model (similar to ConnectWise Manage's boards/queues) —
  there's no flat "list all tickets" endpoint; you search within a board.
