#!/usr/bin/env node

import { Command } from "commander";
import { scan } from "./scanner.js";
import { formatText } from "./reporters/text.js";
import { formatJson } from "./reporters/json.js";
import { formatSarif } from "./reporters/sarif.js";
import type { OutputFormat, Severity } from "./analyzers/types.js";

const program = new Command();

program
  .name("sigil")
  .description("Security scanner for MCP (Model Context Protocol) servers")
  .version("0.2.2")
  .argument("<target>", "Path to MCP server directory, file, or config")
  .option("-o, --output <format>", "Output format: text, json, sarif", "text")
  .option(
    "-s, --severity <level>",
    "Minimum severity to report: low, medium, high, critical",
    "low"
  )
  .option("--no-color", "Disable colored output")
  .option("--config <path>", "Path to scanner config file (.mcp-scanner.yml)")
  .option("--ignore <rules>", "Comma-separated rule IDs to ignore")
  .option("-q, --quiet", "Only output findings (no banner, no summary)")
  .option("-v, --verbose", "Show detailed analysis trace")
  .action(async (target: string, opts) => {
    const format = opts.output as OutputFormat;
    const minSeverity = opts.severity as Severity;
    const ignoreRules = opts.ignore
      ? (opts.ignore as string).split(",").map((r: string) => r.trim())
      : [];

    try {
      const result = await scan(target, {
        minSeverity,
        ignoreRules,
        configPath: opts.config as string | undefined,
        verbose: opts.verbose as boolean,
      });

      let output: string;
      switch (format) {
        case "json":
          output = formatJson(result);
          break;
        case "sarif":
          output = formatSarif(result);
          break;
        case "text":
        default:
          output = formatText(result, {
            color: opts.color !== false,
            quiet: opts.quiet as boolean,
          });
          break;
      }

      process.stdout.write(output + "\n");

      // Exit code: 0 if PASS, 1 if FAIL/WARN
      process.exit(result.score.value >= 70 ? 0 : 1);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Error: ${message}\n`);
      process.exit(2);
    }
  });

program.parse();
