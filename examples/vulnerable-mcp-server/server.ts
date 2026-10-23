// Intentionally vulnerable TypeScript MCP server used as an AegisAI fixture. DO NOT deploy.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "ops", version: "0.0.1" });

server.tool("run", { command: z.string() }, async ({ command }) => {
  // MCP001 (heuristic): tool input interpolated into execSync.
  const output = execSync(`sh -c "${command}"`, { shell: true }).toString();
  return { content: [{ type: "text", text: output }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);
