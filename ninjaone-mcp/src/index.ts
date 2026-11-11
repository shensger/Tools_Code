#!/usr/bin/env node
/**
 * NinjaOne MCP Server
 *
 * Provides tools for interacting with the NinjaOne RMM platform via the
 * Model Context Protocol. Covers devices, organizations, alerts, scripts,
 * tickets, and inventory queries.
 *
 * Environment variables:
 *   NINJAONE_CLIENT_ID     - OAuth 2.0 Client ID (required)
 *   NINJAONE_CLIENT_SECRET - OAuth 2.0 Client Secret (required)
 *   NINJAONE_REGION        - API region: 'us' | 'eu' | 'oc' (default: 'us')
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerDeviceTools } from "./tools/devices.js";
import { registerDeviceHardwareTools } from "./tools/device-hardware.js";
import { registerDeviceConfigTools } from "./tools/device-config.js";
import { registerDevicePatchingTools } from "./tools/device-patching.js";
import { registerGroupTools } from "./tools/groups.js";
import { registerOrganizationTools } from "./tools/organizations.js";
import { registerPolicyTools } from "./tools/policies.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerScriptTools } from "./tools/scripts.js";
import { registerTicketTools } from "./tools/tickets.js";
import { registerQueryTools } from "./tools/queries.js";

// ─── Server Setup ─────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "ninjaone-mcp-server",
  version: "1.1.0",
});

// Register all tool domains
registerDeviceTools(server);
registerDeviceHardwareTools(server);
registerDeviceConfigTools(server);
registerDevicePatchingTools(server);
registerGroupTools(server);
registerOrganizationTools(server);
registerPolicyTools(server);
registerAlertTools(server);
registerScriptTools(server);
registerTicketTools(server);
registerQueryTools(server);

// ─── Entry Point ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const clientId = process.env["NINJAONE_CLIENT_ID"];
  const clientSecret = process.env["NINJAONE_CLIENT_SECRET"];

  if (!clientId || !clientSecret) {
    console.error(
      "ERROR: NINJAONE_CLIENT_ID and NINJAONE_CLIENT_SECRET environment variables are required.\n" +
      "Set them in your Claude Desktop config or shell environment.\n\n" +
      "Claude Desktop config example:\n" +
      JSON.stringify(
        {
          mcpServers: {
            ninjaone: {
              command: "node",
              args: ["dist/index.js"],
              env: {
                NINJAONE_CLIENT_ID: "your-client-id",
                NINJAONE_CLIENT_SECRET: "your-client-secret",
                NINJAONE_REGION: "us",
              },
            },
          },
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  const region = process.env["NINJAONE_REGION"] ?? "us";
  console.error(`NinjaOne MCP Server starting (region: ${region})...`);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("NinjaOne MCP Server running via stdio.");
}

main().catch((err: unknown) => {
  console.error("Fatal error:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
