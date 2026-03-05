import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "child_process";
import { promisify } from "util";
import * as fs from "fs/promises";
import * as path from "path";

const execFileAsync = promisify(execFile);

const server = new McpServer({
  name: "safe-server",
  version: "1.0.0",
});

const WORKSPACE_DIR = "/data/workspace";
const ALLOWED_COMMANDS = ["git", "ls", "cat"] as const;
const SAFE_ENV_VARS = ["NODE_ENV", "APP_VERSION", "PORT"];

// Safe: Uses execFile (not exec) with an allowlist of commands
server.tool(
  "run_command",
  "Run an allowed command in the workspace",
  {
    command: z.enum(ALLOWED_COMMANDS),
    args: z.array(z.string()).max(10),
  },
  async ({ command, args }) => {
    const { stdout } = await execFileAsync(command, args, {
      cwd: WORKSPACE_DIR,
    });
    return {
      content: [{ type: "text", text: stdout }],
    };
  }
);

// Safe: Validates path is within allowed directory using realpath
server.tool(
  "read_file",
  "Read a file from the workspace directory",
  {
    filePath: z.string().max(255),
  },
  async ({ filePath }) => {
    const resolved = await fs.realpath(path.join(WORKSPACE_DIR, filePath));
    if (!resolved.startsWith(WORKSPACE_DIR)) {
      throw new Error("Access denied: path outside workspace");
    }
    const content = await fs.readFile(resolved, "utf-8");
    return {
      content: [{ type: "text", text: content }],
    };
  }
);

// Safe: Returns only allowlisted environment variables
server.tool(
  "get_config",
  "Get application configuration values",
  {},
  async () => {
    const config = Object.fromEntries(
      SAFE_ENV_VARS.map((key) => [key, process.env[key] ?? "not set"])
    );
    return {
      content: [{ type: "text", text: JSON.stringify(config, null, 2) }],
    };
  }
);

// Safe: Uses z.enum for constrained input, no injection vector
server.tool(
  "get_status",
  "Get the status of a service",
  {
    service: z.enum(["api", "database", "cache"]),
  },
  async ({ service }) => {
    const statuses: Record<string, string> = {
      api: "healthy",
      database: "healthy",
      cache: "degraded",
    };
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ service, status: statuses[service] }),
        },
      ],
    };
  }
);

// Safe: Error handler returns sanitized message, not stack trace
server.tool(
  "process_data",
  "Process some data",
  {
    input: z.string().max(1000),
  },
  async ({ input }) => {
    try {
      const result = input.toUpperCase();
      return {
        content: [{ type: "text", text: result }],
      };
    } catch {
      return {
        content: [
          { type: "text", text: "An error occurred while processing data." },
        ],
      };
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
