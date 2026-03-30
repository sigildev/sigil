import type { AnalysisContext, Finding } from "../analyzers/types.js";
import { findLineNumber, shouldSkipFile, isComment } from "./utils.js";

export function detectDebugMode(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  const DEBUG_PATTERNS = [
    /\bDEBUG\s*[:=]\s*(?:true|1|["']true["'])/gi,
    /\bdebug\s*[:=]\s*true/g,
    /NODE_ENV\s*[:=!]=?\s*["']development["']/g,
    /\.use\s*\(\s*\w*[Dd]ebug/g,
    // Python: only match actual debug enablement, not constant references
    /\bbasicConfig\s*\([^)]*level\s*=\s*logging\.DEBUG/g,
    /\bsetLevel\s*\(\s*logging\.DEBUG\s*\)/g,
    /\blevel\s*=\s*logging\.DEBUG\b/g,
    /log_level\s*=\s*["']debug["']/gi,
  ];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;

    for (const pattern of DEBUG_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        // Skip if it's in a conditional check (e.g., if (NODE_ENV === 'development'))
        if (/if\s*\(/.test(lineContent) || /if\s+/.test(lineContent)) continue;

        // Skip Python logging.DEBUG constant references (dict lookups, comparisons, isEnabledFor)
        if (/isEnabledFor\s*\(\s*logging\.DEBUG/.test(lineContent)) continue;
        if (/logging\.DEBUG\s*[:\]}),]/.test(lineContent) && !/level\s*=/.test(lineContent)) continue;

        findings.push({
          ruleId: "MCS-CFG-001",
          severity: "medium",
          title: "Debug Mode Enabled",
          message: `Debug or development configuration appears to be enabled. Ensure this is disabled in production.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Use environment-based configuration to disable debug mode in production.",
          },
        });
      }
    }
  }

  return findings;
}

export function detectVerboseErrors(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  const VERBOSE_PATTERNS_TS = [
    /\.stack\b/g,
    /error\.message\b/g,
    /JSON\.stringify\s*\(\s*(?:err|error)\b/g,
    /console\.error\s*\(\s*(?:err|error)\b/g,
  ];

  const VERBOSE_PATTERNS_PY = [
    /traceback\.format_exc/g,
    /traceback\.print_exc/g,
    /str\s*\(\s*(?:e|err|error|exception)\s*\)/g,
  ];

  const patterns =
    context.language === "python" ? VERBOSE_PATTERNS_PY :
    context.language === "typescript" ? VERBOSE_PATTERNS_TS :
    [...VERBOSE_PATTERNS_TS, ...VERBOSE_PATTERNS_PY];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;

    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        // Only flag if it's in a catch block or error handler that returns to client
        const before = content.slice(Math.max(0, match.index - 500), match.index);
        const isInCatchBlock = /catch\s*\(|except\s+/.test(before);
        const returnsToClient = /return\s*\{|content.*text/.test(
          content.slice(match.index, Math.min(content.length, match.index + 200))
        );

        if (isInCatchBlock && (returnsToClient || /\.stack/.test(lineContent) || /traceback/.test(lineContent))) {
          findings.push({
            ruleId: "MCS-CFG-002",
            severity: "low",
            title: "Verbose Error Messages",
            message: `Error handler returns detailed error information (stack traces, internal paths). This leaks implementation details.`,
            location: { file, startLine: line, endLine: line },
            fix: {
              description: "Return generic error messages to the client. Log detailed errors server-side only.",
              suggestion: 'return { content: [{ type: "text", text: "An error occurred. Please try again." }] };',
            },
          });
          break; // One per file is enough for this rule
        }
      }
    }
  }

  return findings;
}

export function detectInsecureTransport(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  const TRANSPORT_PATTERNS = [
    { pattern: /(?:host|bind|listen)\s*[:=]\s*["']0\.0\.0\.0["']/g, label: "Server binds to all interfaces (0.0.0.0)" },
    { pattern: /cors\s*[:=]\s*\{\s*origin\s*[:=]\s*["']\*["']/g, label: "CORS allows all origins" },
    { pattern: /Access-Control-Allow-Origin['":\s]*\*/g, label: "CORS allows all origins" },
  ];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;

    for (const { pattern, label } of TRANSPORT_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        findings.push({
          ruleId: "MCS-CFG-003",
          severity: "medium",
          title: "Insecure Transport Configuration",
          message: `${label}. This may expose the MCP server to unauthorized access.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Bind to localhost (127.0.0.1), use specific CORS origins, and enable TLS for HTTP transport.",
          },
        });
      }
    }
  }

  return findings;
}
