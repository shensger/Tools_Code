# Build brief for Claude: install the NinjaOne MCP server for an end user

**How to use this file:** paste the line below into Claude (Claude Desktop with Desktop Commander,
or Claude Code) on the end user's computer:

> Follow the instructions in https://github.com/shensger/tools_code/blob/main/ninjaone-mcp/CLAUDE_BUILD.md
> to install the NinjaOne MCP server on this machine for me.

If Claude can't open the link (private repo), attach this file to the chat instead.

Everything below is addressed to Claude.

---

## Your task

Install the NinjaOne MCP server from `shensger/tools_code` (folder `ninjaone-mcp`) on this computer
and register it in the user's Claude Desktop config so its 65 `ninjaone_*` tools load.
The human-readable version of these steps is `SETUP.md` in the same folder; use it for detail
and troubleshooting.

## Ground rules

- **You need a real shell on this machine** (Desktop Commander, Claude Code, or similar). If you
  don't have one, stop and tell the user to give you one or to follow `SETUP.md` themselves.
- **Never print, log or repeat the Client Secret** in chat, in command output or in files other
  than `claude_desktop_config.json`. Don't put it in shell history: write the config with a script
  that reads the value, not by echoing it in a command line where you can avoid it.
- **Back up `claude_desktop_config.json` before editing it** and **merge** into it; never drop other
  servers already configured.
- Ask before installing software (Node.js, Git). Don't use admin/sudo unless the user agrees.
- Do one step at a time and check its result before moving on. If a step fails, use the
  troubleshooting table in `SETUP.md` before improvising.

## Step 1 — Detect the environment

Determine and report back in one short message:

- OS (Windows / macOS) and the user's home folder.
- `node -v` (needs **>= 18**), `npm -v`, `git --version`.
- Claude Desktop config path:
  - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
  - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Whether that file exists and whether it already has an `mcpServers.ninjaone` entry. If it does,
  ask whether to replace it or stop.

If Node or Git is missing, offer to install it (Windows: `winget install OpenJS.NodeJS.LTS` /
`winget install Git.Git`; macOS: `brew install node git`). After a Windows install, start a new
shell so PATH updates.

## Step 2 — Collect what you need from the user

Ask for these in a single message:

1. **NinjaOne region** — the host they sign in at: `app.ninjarmm.com` → `us`, `eu.ninjarmm.com` →
   `eu`, `oc.ninjarmm.com` → `oc`.
2. **Client ID and Client Secret** of a NinjaOne API app. If they don't have one, walk them through
   `SETUP.md` section 2. The essentials: **Administration > Apps > API > Client App IDs > Add**,
   platform **API Services (machine-to-machine)**, scopes **Monitoring + Management + Control**
   (all three are required — the server requests all three), grant type **Client Credentials**,
   no redirect URI. The secret is only shown once.
3. **Install folder** — default to the home folder (`<home>/tools_code/ninjaone-mcp`). Don't use
   Downloads, Desktop, a temp folder or a synced folder like OneDrive.

## Step 3 — Get the code

From the install parent (default: home folder):

```
git clone --filter=blob:none --sparse https://github.com/shensger/tools_code.git
cd tools_code
git sparse-checkout set ninjaone-mcp
```

If the clone asks for credentials or returns 404, the repo is private and the user's GitHub account
lacks access. Tell them; don't try to work around it. Alternative: they can send the
`ninjaone-mcp` folder as a zip, which you then extract to the install folder.

If `tools_code` already exists there, `git pull` instead of cloning.

## Step 4 — Build

In `tools_code/ninjaone-mcp`:

```
npm ci
npm run build
```

Confirm `dist/index.js` exists. Record its **absolute path**.

If `npm ci` fails on lockfile mismatch, fall back to `npm install`.

## Step 5 — Test the credentials before touching Claude's config

Run a direct token request so a bad ID/secret/region shows up here, not as a silent failure in
Claude Desktop. Read the secret from a variable you set without echoing it; print only the status.

PowerShell:

```powershell
$body = @{ grant_type='client_credentials'; client_id=$id; client_secret=$secret; scope='monitoring management control' }
$r = Invoke-RestMethod -Method Post -Uri "https://<region-host>/ws/oauth/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
"token ok, expires_in=$($r.expires_in)"
```

bash:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://<region-host>/ws/oauth/token" \
  -d grant_type=client_credentials -d "client_id=$ID" -d "client_secret=$SECRET" \
  --data-urlencode "scope=monitoring management control"
```

`<region-host>` is `app.ninjarmm.com`, `eu.ninjarmm.com` or `oc.ninjarmm.com`.

- 200 / token returned → continue.
- 401 / `invalid_client` → wrong ID/secret or wrong region; ask the user to re-check.
- `invalid_scope` → one of the three scopes isn't ticked on the API app.

## Step 6 — Register in Claude Desktop

1. Copy the config to `claude_desktop_config.json.bak-<yyyyMMdd-HHmm>` in the same folder
   (create an empty `{ "mcpServers": {} }` file first if none exists).
2. Parse the JSON, add or replace only `mcpServers.ninjaone`, write it back as valid JSON. Use a
   real JSON parser (PowerShell `ConvertFrom-Json`/`ConvertTo-Json -Depth 20`, or `node -e`), not
   string concatenation. The entry:

```json
"ninjaone": {
  "command": "node",
  "args": ["<absolute path to dist/index.js>"],
  "env": {
    "NINJAONE_CLIENT_ID": "<client id>",
    "NINJAONE_CLIENT_SECRET": "<client secret>",
    "NINJAONE_REGION": "<us|eu|oc>"
  }
}
```

3. On macOS, or if Node came from nvm/Homebrew/a non-default path, set `"command"` to the absolute
   path from `which node` / `(Get-Command node).Source`; GUI apps don't inherit the shell PATH.
4. Re-read the file and parse it once more to prove it is valid JSON and that every other server
   entry is still present. Report the list of server names before and after.

## Step 7 — Restart and verify

1. Tell the user to **fully quit** Claude Desktop (Windows: tray icon > Quit; macOS: Cmd+Q) and
   reopen it. If you're running inside Claude Desktop yourself, this ends your session, so give the
   verification steps below *before* asking them to restart.
2. In a new chat they should see **ninjaone** in the tools/connectors menu.
3. First test prompt: *"List my NinjaOne organizations."*
4. If the server doesn't load, read the log: Windows `%APPDATA%\Claude\logs\mcp-server-ninjaone.log`,
   macOS `~/Library/Logs/Claude/mcp-server-ninjaone.log`, and match against the table in `SETUP.md`.

## Step 8 — Hand-off message to the user

Finish with a short summary:

- Where it's installed and where the config backup is.
- That some tools make changes (reboot, run script, service control, delete alert, policy and org
  changes, custom field writes) and Claude will ask before running each one — keep approvals on.
- How to update: `git pull` in `tools_code`, then `npm ci && npm run build` in `ninjaone-mcp`, then
  restart Claude Desktop.
- That the Client Secret lives in plain text in `claude_desktop_config.json`, so that file shouldn't
  be shared or synced.

Do **not** include the secret in the summary.
