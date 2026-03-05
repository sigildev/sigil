import { readFile } from "node:fs/promises";
import type { ConfigEntry } from "../analyzers/types.js";

/**
 * Parse an MCP configuration file (claude_desktop_config.json, .mcp.json)
 * and extract server entries.
 */
export async function parseConfig(configPath: string): Promise<ConfigEntry[]> {
  const raw = await readFile(configPath, "utf-8");
  const config = JSON.parse(raw);

  const entries: ConfigEntry[] = [];

  // Handle both { mcpServers: {...} } and { servers: {...} } formats
  const servers = config.mcpServers ?? config.servers ?? {};

  for (const [name, value] of Object.entries(servers)) {
    const server = value as Record<string, unknown>;
    entries.push({
      name,
      command: (server.command as string) ?? "",
      args: server.args as string[] | undefined,
      env: server.env as Record<string, string> | undefined,
    });
  }

  return entries;
}
