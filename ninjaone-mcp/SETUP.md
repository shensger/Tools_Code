# NinjaOne MCP Server — Setup Guide

Step-by-step install of the NinjaOne MCP server into Claude Desktop on Windows or macOS.
Allow about 15 minutes, most of it creating the API app in NinjaOne.

> **Handing this to Claude to do the install?** Use [`CLAUDE_BUILD.md`](CLAUDE_BUILD.md) instead.
> It is written as a brief Claude can follow end to end on the user's machine.

---

## What you get

65 tools across devices, hardware/software inventory, patching, fleet-wide queries, groups,
organizations, policies, alerts, scripts/jobs and tickets. The full list is in [`README.md`](README.md).

Some tools **change things**: `ninjaone_reboot_device`, `ninjaone_run_script_or_action`,
`ninjaone_control_windows_service`, `ninjaone_delete_alert`, `ninjaone_create_policy`,
`ninjaone_set_organization_policy_mappings`, `ninjaone_approve_devices`,
`ninjaone_update_device_custom_fields`, the create/update organization, location and ticket tools,
and the maintenance-window tools. Claude Desktop asks for approval before each tool call by default;
leave that on for these tools unless you know the user.

---

## 1. Prerequisites

| Item | Requirement | Check |
|------|-------------|-------|
| Claude Desktop | Current version, signed in | Open the app |
| Node.js | **18 or later** (LTS 20/22/24 recommended) | `node -v` |
| npm | Comes with Node.js | `npm -v` |
| Git | Any recent version | `git --version` |
| GitHub access | Read access to `shensger/tools_code` (private repos need a login) | `git ls-remote https://github.com/shensger/tools_code` |
| NinjaOne | An account allowed to create API apps (**Administration > Apps > API**) | — |

Install Node.js if missing:

- **Windows:** `winget install OpenJS.NodeJS.LTS` (then open a **new** terminal)
- **macOS:** `brew install node` or the installer from nodejs.org

---

## 2. Create the NinjaOne API application

NinjaOne has two kinds of API app. You need the **machine-to-machine** one.

1. Sign in to NinjaOne and go to **Administration > Apps > API**.
2. Open the **Client App IDs** tab and click **Add client app id**.
3. **Application Platform:** `API Services (machine-to-machine)` — *not* Web, Native or SPA.
4. **Name:** something identifiable, e.g. `Claude MCP – <user name>`.
5. **Redirect URIs:** leave blank.
6. **Scopes:** tick **Monitoring**, **Management** and **Control**.
   - The server requests all three scopes when it gets a token, so **all three must be ticked**
     or authentication fails.
   - Control is what scripts, reboots and service control use.
7. **Allowed Grant Types:** `Client Credentials`.
8. Click **Save**. NinjaOne shows the **Client ID** and **Client Secret** once. Copy both into a
   password manager now; the secret cannot be shown again (you'd have to generate a new one).

Also note the **region** from the URL you sign in at:

| You sign in at | `NINJAONE_REGION` |
|----------------|-------------------|
| `app.ninjarmm.com` | `us` |
| `eu.ninjarmm.com` | `eu` |
| `oc.ninjarmm.com` | `oc` |

---

## 3. Get the code and build it

Pick a permanent folder; Claude Desktop runs the server from here, so don't use Downloads or a temp folder.

**Windows (PowerShell):**

```powershell
cd $env:USERPROFILE
git clone --filter=blob:none --sparse https://github.com/shensger/tools_code.git
cd tools_code
git sparse-checkout set ninjaone-mcp
cd ninjaone-mcp
npm ci
npm run build
```

**macOS (Terminal):**

```bash
cd ~
git clone --filter=blob:none --sparse https://github.com/shensger/tools_code.git
cd tools_code
git sparse-checkout set ninjaone-mcp
cd ninjaone-mcp
npm ci
npm run build
```

The sparse checkout pulls only this folder, not the rest of the repo.

Confirm the build produced the entry point:

- Windows: `Test-Path .\dist\index.js` → `True`
- macOS: `ls dist/index.js`

Write down the **full path** to `dist/index.js`, for example:

- Windows: `C:\Users\jsmith\tools_code\ninjaone-mcp\dist\index.js`
- macOS: `/Users/jsmith/tools_code/ninjaone-mcp/dist/index.js`

---

## 4. Quick test before touching Claude (optional, recommended)

This proves the credentials work, independent of Claude Desktop.

**Windows:**

```powershell
$env:NINJAONE_CLIENT_ID="<client id>"
$env:NINJAONE_CLIENT_SECRET="<client secret>"
$env:NINJAONE_REGION="us"
npx @modelcontextprotocol/inspector node dist/index.js
```

**macOS:**

```bash
NINJAONE_CLIENT_ID="<client id>" NINJAONE_CLIENT_SECRET="<client secret>" NINJAONE_REGION="us" \
  npx @modelcontextprotocol/inspector node dist/index.js
```

A browser tab opens. Click **Connect > Tools > List Tools**, run `ninjaone_list_organizations`,
and you should see the organizations. Close the terminal when done (this clears the variables).

---

## 5. Add the server to Claude Desktop

1. In Claude Desktop open **Settings > Developer > Edit Config**. This opens
   `claude_desktop_config.json`:
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
2. **Back the file up first.**
3. Add a `ninjaone` entry inside `mcpServers`. If `mcpServers` already has other servers, add
   this alongside them — don't replace them.

**Windows** (note the doubled backslashes):

```json
{
  "mcpServers": {
    "ninjaone": {
      "command": "node",
      "args": ["C:\\Users\\jsmith\\tools_code\\ninjaone-mcp\\dist\\index.js"],
      "env": {
        "NINJAONE_CLIENT_ID": "<client id>",
        "NINJAONE_CLIENT_SECRET": "<client secret>",
        "NINJAONE_REGION": "us"
      }
    }
  }
}
```

**macOS:**

```json
{
  "mcpServers": {
    "ninjaone": {
      "command": "node",
      "args": ["/Users/jsmith/tools_code/ninjaone-mcp/dist/index.js"],
      "env": {
        "NINJAONE_CLIENT_ID": "<client id>",
        "NINJAONE_CLIENT_SECRET": "<client secret>",
        "NINJAONE_REGION": "us"
      }
    }
  }
}
```

> **macOS + Homebrew/nvm:** Claude Desktop doesn't load your shell profile, so `node` may not be
> found. Use the full path from `which node` as `"command"`, e.g. `"/opt/homebrew/bin/node"`.

4. Save, then **fully quit** Claude Desktop (Windows: system tray icon > Quit; macOS: Cmd+Q) and
   reopen it. Closing the window is not enough.

---

## 6. Verify

1. In a new chat, open the tools/connectors menu — **ninjaone** should be listed with its tools.
2. Ask: *"List my NinjaOne organizations."* Approve the tool call. You should get the org list.
3. Ask: *"How many Windows servers are offline?"* to exercise a filtered query.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `ninjaone` not in the tools list | JSON syntax error (trailing comma, single backslashes) or app not fully restarted. Validate the JSON and quit from the tray / Cmd+Q. |
| Server shows as failed | Check the log: Windows `%APPDATA%\Claude\logs\mcp-server-ninjaone.log`, macOS `~/Library/Logs/Claude/mcp-server-ninjaone.log`. |
| `Cannot find module ...dist\index.js` | Path is wrong or `npm run build` wasn't run. |
| `'node' is not recognized` / `spawn node ENOENT` | Node not installed or not on PATH for GUI apps. Use the full path to `node.exe` / `node` as `"command"`. |
| `NINJAONE_CLIENT_ID and NINJAONE_CLIENT_SECRET ... are required` | The `env` block is missing or misspelled. |
| `Error: Unauthorized` (401) | Wrong ID/secret, wrong region, or app isn't machine-to-machine with Client Credentials. |
| Token request fails with `invalid_scope` | Monitoring, Management **and** Control must all be ticked on the API app. |
| `Error: Permission denied` (403) | The scope for that tool is missing, or the API app's access is restricted. |
| `Rate limit exceeded` (429) | Wait and retry; narrow large queries with `device_filter` / page size. |

---

## 8. Updating

```powershell
cd <install folder>\tools_code
git pull
cd ninjaone-mcp
npm ci
npm run build
```

Then fully restart Claude Desktop.

## 9. Removing

1. Delete the `ninjaone` block from `claude_desktop_config.json` and restart Claude Desktop.
2. Delete the `tools_code` folder.
3. In NinjaOne, **Administration > Apps > API**, delete the client app so the secret stops working.

## Security notes

- The Client Secret gives API access at the scopes you granted across **every organization** the
  app can see. Treat it like an admin password.
- It is stored in plain text in `claude_desktop_config.json`. Don't sync that file to shared
  storage or commit it anywhere (`.gitignore` here already excludes it).
- Use one API app per user so you can revoke a single person's access.
- Rotate the secret if a laptop is lost or a user leaves.
