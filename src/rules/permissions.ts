import type { AnalysisContext, Finding } from "../analyzers/types.js";
import {
  findLineNumber,
  isInToolHandler,
  shouldSkipFile,
  isComment,
} from "./utils.js";

// Unrestricted outbound HTTP patterns
const BROAD_HTTP_PATTERNS = [
  // fetch with a variable URL (not a string literal)
  /\bfetch\s*\(\s*(?!["'`])\w+/g,
  // axios/http with variable URL
  /\baxios\.\w+\s*\(\s*(?!["'`])\w+/g,
  /\bhttp\.request\s*\(/g,
  /\bhttps\.request\s*\(/g,
  // Python requests
  /\brequests\.\w+\s*\(\s*(?!["'`])\w+/g,
  /\bhttpx\.\w+\s*\(\s*(?!["'`])\w+/g,
];

const HOST_CHECK_PATTERNS = [
  /ALLOWED_HOSTS/i,
  /allowedHosts/i,
  /hostname.*includes/,
  /host.*===?\s*["']/,
  /url.*startsWith/,
  /whitelist/i,
  /allowlist/i,
];

// Arbitrary code execution patterns
const CODE_EXEC_PATTERNS_TS = [
  /\beval\s*\(/g,
  /\bFunction\s*\(\s*["'`]/g,
  /new\s+Function\s*\(/g,
  /\bvm\.runInNewContext\s*\(/g,
  /\bvm\.runInThisContext\s*\(/g,
  /\bvm\.createScript\s*\(/g,
];

const CODE_EXEC_PATTERNS_PY = [
  /(?<!\.)eval\s*\(/g,
  /(?<!\.)exec\s*\(/g,
  /(?<!\.)\bcompile\s*\(\s*(?!["'])/g,
  /\b__import__\s*\(/g,
];

function hasHostValidation(content: string, matchIndex: number): boolean {
  const start = Math.max(0, matchIndex - 800);
  const end = Math.min(content.length, matchIndex + 300);
  const context = content.slice(start, end);
  return HOST_CHECK_PATTERNS.some((p) => p.test(context));
}

export function detectBroadCapabilities(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;

    for (const pattern of BROAD_HTTP_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        if (hasHostValidation(content, match.index)) continue;

        // Only flag if in a tool handler context
        if (!isInToolHandler(content, match.index, context.language)) continue;

        findings.push({
          ruleId: "MCS-PERM-001",
          severity: "high",
          title: "Overly Broad Tool Capabilities",
          message: `Outbound HTTP request with no apparent host restriction. A compromised tool input could exfiltrate data to any URL.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Restrict outbound requests to an allowlist of permitted hosts.",
            suggestion: "if (!ALLOWED_HOSTS.includes(new URL(url).hostname)) throw new Error('Host not allowed');",
          },
        });
      }
    }
  }

  return findings;
}

export function detectUnrestrictedFilesystem(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  const FS_PATTERNS_TS = [
    /\bfs\.readFileSync\s*\(\s*(?!["'`])\w+/g,
    /\bfs\.readFile\s*\(\s*(?!["'`])\w+/g,
    /\bfs\.writeFileSync\s*\(\s*(?!["'`])\w+/g,
    /\bfs\.writeFile\s*\(\s*(?!["'`])\w+/g,
  ];

  const FS_PATTERNS_PY = [
    /\bopen\s*\(\s*(?!["'`])\w+/g,
  ];

  const patterns = context.language === "python" ? FS_PATTERNS_PY :
    context.language === "typescript" ? FS_PATTERNS_TS :
    [...FS_PATTERNS_TS, ...FS_PATTERNS_PY];

  const RESTRICT_PATTERNS = [
    /ALLOWED_DIR/i,
    /allowedDir/i,
    /base_?dir/i,
    /root_?dir/i,
    /startsWith/,
    /startswith/,
    /realpath/,
    /resolve.*startsWith/,
    /prefix/i,
    /whitelist/i,
    /allowlist/i,
  ];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;

    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        // Check for restrictions in surrounding context
        const start = Math.max(0, match.index - 800);
        const end = Math.min(content.length, match.index + 300);
        const ctx = content.slice(start, end);
        if (RESTRICT_PATTERNS.some((p) => p.test(ctx))) continue;

        // Only flag if in a tool handler context
        if (!isInToolHandler(content, match.index, context.language)) continue;

        findings.push({
          ruleId: "MCS-PERM-002",
          severity: "high",
          title: "Unrestricted Filesystem Access",
          message: `File operation accepts a variable path with no directory restriction. Can access any file on the system.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Restrict file operations to an allowed directory. Use realpath() + prefix check.",
          },
        });
      }
    }
  }

  return findings;
}

export function detectArbitraryCodeExecution(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];
  const patterns =
    context.language === "python" ? CODE_EXEC_PATTERNS_PY :
    context.language === "typescript" ? CODE_EXEC_PATTERNS_TS :
    [...CODE_EXEC_PATTERNS_TS, ...CODE_EXEC_PATTERNS_PY];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;

    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        // In Python, exec() with a string literal is less dangerous — skip those
        if (context.language === "python" && /\bexec\s*\(\s*["']/.test(lineContent)) continue;

        // Only flag if in a tool handler context
        if (!isInToolHandler(content, match.index, context.language)) continue;

        findings.push({
          ruleId: "MCS-PERM-003",
          severity: "critical",
          title: "Tool Can Execute Arbitrary Code",
          message: `Code evaluation function (eval/exec/Function) detected in tool handler context. If tool input reaches this, it enables arbitrary code execution.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Remove eval/exec usage. Use an allowlist of permitted operations instead of evaluating user input as code.",
          },
        });
      }
    }
  }

  return findings;
}
