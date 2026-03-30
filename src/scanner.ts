import { resolve } from "node:path";
import { readFile, stat } from "node:fs/promises";
import type {
  ScanResult,
  Finding,
  AnalysisContext,
  Severity,
  ServerInfo,
} from "./analyzers/types.js";
import { computeScore } from "./scoring.js";
import { discoverFiles } from "./discovery/files.js";
import { parseManifest } from "./discovery/manifest.js";
import { parseConfig } from "./discovery/config-parser.js";
import { rules } from "./rules/index.js";
import { detectVulnerableDeps } from "./rules/deps.js";

const PKG_VERSION = "0.2.2";

export interface ScanOptions {
  minSeverity?: Severity;
  ignoreRules?: string[];
  configPath?: string;
  verbose?: boolean;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export async function scan(
  target: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const start = Date.now();
  const rootDir = resolve(target);

  // ─── Layer 1: Discovery ───

  const targetStat = await stat(rootDir);
  const isConfigFile =
    !targetStat.isDirectory() &&
    (target.endsWith(".json") || target.endsWith(".mcp.json"));

  const configEntries = isConfigFile ? await parseConfig(rootDir) : undefined;

  const manifest = await parseManifest(rootDir);
  const language = await detectLanguage(rootDir);
  const sourceFiles = await discoverFiles(rootDir, language);

  // Read all source files into memory
  const sources = new Map<string, string>();
  for (const file of sourceFiles) {
    const fullPath = resolve(rootDir, file);
    try {
      const content = await readFile(fullPath, "utf-8");
      sources.set(file, content);
    } catch {
      // Skip unreadable files
    }
  }

  // Discover MCP server primitives from source
  const server = await discoverServer(sources);

  const context: AnalysisContext = {
    rootDir,
    language,
    sourceFiles,
    sources,
    server,
    manifest,
    configEntries,
  };

  // ─── Layer 2: Analysis ───

  const ignoreSet = new Set(options.ignoreRules ?? []);
  const minSev = options.minSeverity ?? "low";
  const minSevOrder = SEVERITY_ORDER[minSev];

  let findings: Finding[] = [];

  for (const rule of rules) {
    if (ignoreSet.has(rule.id)) continue;
    if (SEVERITY_ORDER[rule.severity] > minSevOrder) continue;

    try {
      const ruleFindings = rule.detect(context);
      findings.push(...ruleFindings);
    } catch {
      // Rule failed — skip silently (don't crash the scan)
    }
  }

  // Run async dependency checker separately
  try {
    if (!ignoreSet.has("MCS-DEP-001")) {
      const depFindings = await detectVulnerableDeps(context);
      for (const f of depFindings) {
        if (SEVERITY_ORDER[f.severity] > minSevOrder) continue;
        findings.push(f);
      }
    }
  } catch {
    // Network errors shouldn't crash the scan
  }

  // Sort: critical first, then by file/line
  findings.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    const fileDiff = a.location.file.localeCompare(b.location.file);
    if (fileDiff !== 0) return fileDiff;
    return a.location.startLine - b.location.startLine;
  });

  // ─── Layer 3: Reporting ───

  const score = computeScore(findings);
  const duration = Date.now() - start;

  return {
    scanner: { name: "sigil", version: PKG_VERSION },
    target: {
      path: target,
      name: manifest?.name,
      version: manifest?.version,
      language,
    },
    server,
    findings,
    score,
    timestamp: new Date().toISOString(),
    duration,
  };
}

async function detectLanguage(
  rootDir: string
): Promise<"typescript" | "python" | "unknown"> {
  try {
    await stat(resolve(rootDir, "package.json"));
    return "typescript";
  } catch {
    // not TS
  }
  try {
    await stat(resolve(rootDir, "pyproject.toml"));
    return "python";
  } catch {
    // not Python
  }
  try {
    await stat(resolve(rootDir, "requirements.txt"));
    return "python";
  } catch {
    // not Python
  }
  try {
    await stat(resolve(rootDir, "setup.py"));
    return "python";
  } catch {
    // not Python
  }
  return "unknown";
}

async function discoverServer(
  _sources: Map<string, string>
): Promise<ServerInfo> {
  // TODO: Parse AST to extract tool/resource/prompt registrations
  return {
    tools: [],
    resources: [],
    prompts: [],
  };
}
