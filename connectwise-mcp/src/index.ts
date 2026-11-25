#!/usr/bin/env node
/**
 * connectwise-mcp-server
 *
 * MCP server exposing the ConnectWise Manage (PSA) REST API as tools:
 *   - Service: tickets, notes, boards, statuses, types, priorities
 *   - Time: time entries, work types, work roles, members
 *   - Company: companies, contacts, sites, configurations (assets)
 *
 * Transport: stdio (default) or streamable HTTP (TRANSPORT=http, PORT=3000).
 * Never log to stdout in stdio mode — use console.error.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./services/client.js";
import { registerCompanyTools } from "./tools/company.js";
import { registerServiceTools } from "./tools/service.js";
import { registerTimeTools } from "./tools/time.js";
import { registerScheduleTools } from "./tools/schedule.js";
import { registerAgreementTools } from "./tools/agreement.js";
import { registerProjectTools } from "./tools/project.js";

const SERVER_VERSION = "1.1.0";

function buildServer(): McpServer {
  const server = new McpServer({ name: "connectwise-mcp-server", version: SERVER_VERSION });
  registerServiceTools(server);
  registerTimeTools(server);
  registerCompanyTools(server);
  registerScheduleTools(server);
  registerAgreementTools(server);
  registerProjectTools(server);
  return server;
}

function printHelp(): void {
  console.error(`connectwise-mcp-server ${SERVER_VERSION}

MCP server for ConnectWise Manage. Runs over stdio by default.

Required environment variables:
  CW_SITE         API host, e.g. api-na.myconnectwise.net (or api-eu / api-au / on-prem host)
  CW_COMPANY_ID   ConnectWise company ID
  CW_PUBLIC_KEY   API member public key
  CW_PRIVATE_KEY  API member private key
  CW_CLIENT_ID    Developer clientId (https://developer.connectwise.com/ClientID)

Optional:
  CW_CODEBASE     default v4_6_release
  CW_API_VERSION  default 2025.1
  TRANSPORT       stdio (default) | http
  PORT            HTTP port when TRANSPORT=http (default 3000)
`);
}

async function runStdio(): Promise<void> {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`connectwise-mcp-server ${SERVER_VERSION} running on stdio (site: ${loadConfig().site})`);
}

async function runHttp(): Promise<void> {
  const { createServer } = await import("node:http");
  const { StreamableHTTPServerTransport } = await import("@modelcontextprotocol/sdk/server/streamableHttp.js");

  const port = parseInt(process.env.PORT || "3000", 10);
  const httpServer = createServer(async (req, res) => {
    if (req.url !== "/mcp") {
      res.writeHead(404).end();
      return;
    }
    // Basic DNS-rebinding protection for local use.
    const host = req.headers.host ?? "";
    if (!/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host) && process.env.CW_MCP_ALLOW_ANY_HOST !== "1") {
      res.writeHead(403).end("Forbidden host");
      return;
    }
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);

    let body: unknown = undefined;
    if (req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const raw = Buffer.concat(chunks).toString("utf8");
      body = raw ? JSON.parse(raw) : undefined;
    }
    await transport.handleRequest(req, res, body);
  });

  httpServer.listen(port, "127.0.0.1", () => {
    console.error(`connectwise-mcp-server ${SERVER_VERSION} running on http://127.0.0.1:${port}/mcp`);
  });
}

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    printHelp();
    return;
  }
  try {
    loadConfig(); // fail fast with a clear message
  } catch (e) {
    console.error(`ERROR: ${(e as Error).message}`);
    printHelp();
    process.exit(1);
  }

  if ((process.env.TRANSPORT || "stdio").toLowerCase() === "http") {
    await runHttp();
  } else {
    await runStdio();
  }
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
