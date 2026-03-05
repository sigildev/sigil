import type { RuleDefinition, AnalysisContext, Finding } from "../analyzers/types.js";
import { detectCommandInjection, detectSqlInjection, detectPathTraversal } from "./injection.js";
import { detectBroadCapabilities, detectUnrestrictedFilesystem, detectArbitraryCodeExecution } from "./permissions.js";
import { detectEnvVarExposure, detectCredentialLeakage } from "./data.js";
import { detectMissingInputSchema } from "./validation.js";
import { detectSuspiciousDescriptions } from "./description.js";
import { detectHardcodedCredentials, detectSecretsInConfig } from "./auth.js";
import { detectDebugMode, detectVerboseErrors, detectInsecureTransport } from "./config.js";
import { detectVulnerableDeps } from "./deps.js";

// Wrapper to handle both sync and async detect functions uniformly
function syncDetect(fn: (ctx: AnalysisContext) => Finding[]): (ctx: AnalysisContext) => Finding[] {
  return fn;
}

export const rules: RuleDefinition[] = [
  // ─── Injection ───
  {
    id: "MCS-INJ-001",
    name: "Command Injection via Tool Input",
    severity: "critical",
    category: "injection",
    description:
      "User-controlled tool inputs passed to shell execution functions (exec, execSync, spawn with shell: true)",
    detect: syncDetect(detectCommandInjection),
  },
  {
    id: "MCS-INJ-002",
    name: "SQL Injection via Tool Input",
    severity: "critical",
    category: "injection",
    description:
      "Tool inputs concatenated into SQL strings without parameterized queries",
    detect: syncDetect(detectSqlInjection),
  },
  {
    id: "MCS-INJ-003",
    name: "Path Traversal in File Operations",
    severity: "high",
    category: "injection",
    description:
      "Tool inputs used in file paths without canonicalization or directory restriction",
    detect: syncDetect(detectPathTraversal),
  },

  // ─── Permissions ───
  {
    id: "MCS-PERM-001",
    name: "Overly Broad Tool Capabilities",
    severity: "high",
    category: "permissions",
    description:
      "Tools performing dangerous operations (file write, network, exec, DB mutations) without scope restrictions",
    detect: syncDetect(detectBroadCapabilities),
  },
  {
    id: "MCS-PERM-002",
    name: "Unrestricted Filesystem Access",
    severity: "high",
    category: "permissions",
    description:
      "File system tools with no directory allowlist or path prefix restriction",
    detect: syncDetect(detectUnrestrictedFilesystem),
  },
  {
    id: "MCS-PERM-003",
    name: "Tool Can Execute Arbitrary Code",
    severity: "critical",
    category: "permissions",
    description:
      "Tools that evaluate user input as code (eval, Function, exec in Python, vm.runInNewContext)",
    detect: syncDetect(detectArbitraryCodeExecution),
  },

  // ─── Data Exfiltration ───
  {
    id: "MCS-DATA-001",
    name: "Environment Variable Exposure",
    severity: "high",
    category: "data-exfiltration",
    description:
      "Tools or resources that return process.env / os.environ without filtering",
    detect: syncDetect(detectEnvVarExposure),
  },
  {
    id: "MCS-DATA-002",
    name: "Credential Leakage in Tool Responses",
    severity: "high",
    category: "data-exfiltration",
    description:
      "Tool responses that include raw API responses containing auth tokens or credentials without redaction",
    detect: syncDetect(detectCredentialLeakage),
  },

  // ─── Input Validation ───
  {
    id: "MCS-VALID-001",
    name: "Missing Input Schema",
    severity: "medium",
    category: "validation",
    description:
      "Tools registered without input validation schemas (empty inputSchema or no Zod/JSON Schema)",
    detect: syncDetect(detectMissingInputSchema),
  },

  // ─── Tool Description Integrity ───
  {
    id: "MCS-DESC-001",
    name: "Suspicious Instructions in Tool Descriptions",
    severity: "high",
    category: "description",
    description:
      "Tool descriptions containing prompt injection patterns: override instructions, exfiltration URLs, cross-tool manipulation",
    detect: syncDetect(detectSuspiciousDescriptions),
  },

  // ─── Authentication & Secrets ───
  {
    id: "MCS-AUTH-001",
    name: "Hardcoded Credentials",
    severity: "critical",
    category: "auth",
    description:
      "API keys, tokens, passwords, or connection strings hardcoded in server source",
    detect: syncDetect(detectHardcodedCredentials),
  },
  {
    id: "MCS-AUTH-002",
    name: "Secrets in MCP Configuration",
    severity: "high",
    category: "auth",
    description:
      "API keys or tokens directly in MCP config files (env block) rather than referenced from environment",
    detect: syncDetect(detectSecretsInConfig),
  },

  // ─── Configuration ───
  {
    id: "MCS-CFG-001",
    name: "Debug Mode Enabled",
    severity: "medium",
    category: "config",
    description:
      "Debug or development configuration left enabled in production builds",
    detect: syncDetect(detectDebugMode),
  },
  {
    id: "MCS-CFG-002",
    name: "Verbose Error Messages",
    severity: "low",
    category: "config",
    description:
      "Error handlers that return full stack traces, internal paths, or system information to the client",
    detect: syncDetect(detectVerboseErrors),
  },
  {
    id: "MCS-CFG-003",
    name: "Insecure Transport Configuration",
    severity: "medium",
    category: "config",
    description:
      "HTTP servers without TLS, servers binding to 0.0.0.0, CORS configured with wildcard origin",
    detect: syncDetect(detectInsecureTransport),
  },

  // ─── Dependencies ───
  {
    id: "MCS-DEP-001",
    name: "Known Vulnerable Dependencies",
    severity: "high",
    category: "dependencies",
    description:
      "Dependencies with known CVEs in package-lock.json / requirements.txt",
    detect: (_ctx: AnalysisContext): Finding[] => {
      // DEP-001 is async (network call to OSV.dev) — skip in sync rule loop.
      // It's called separately in scanner.ts.
      return [];
    },
  },
];
