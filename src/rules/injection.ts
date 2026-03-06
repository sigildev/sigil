import type { AnalysisContext, Finding } from "../analyzers/types.js";
import {
  findLineNumber,
  isInToolHandler,
  shouldSkipFile,
  isComment,
} from "./utils.js";

// Dangerous shell execution sinks (TS/JS)
const EXEC_PATTERNS_TS = [
  /(?<!\.)exec\s*\(/g,
  /(?<!\.)execSync\s*\(/g,
  /(?<!\.)execAsync\s*\(/g,
  /\bspawn\s*\([^)]*shell\s*:\s*true/g,
  /\bspawnSync\s*\([^)]*shell\s*:\s*true/g,
  /child_process\.\s*exec\s*\(/g,
];

// Dangerous shell execution sinks (Python)
const EXEC_PATTERNS_PY = [
  /\bos\.system\s*\(/g,
  /\bos\.popen\s*\(/g,
  /\bsubprocess\.run\s*\([^)]*shell\s*=\s*True/g,
  /\bsubprocess\.call\s*\([^)]*shell\s*=\s*True/g,
  /\bsubprocess\.Popen\s*\([^)]*shell\s*=\s*True/g,
  /\bsubprocess\.check_output\s*\([^)]*shell\s*=\s*True/g,
];

// SQL injection patterns
const SQL_CONCAT_TS = [
  /(?:query|execute|prepare|raw)\s*\(\s*`[^`]*\$\{/g,
  /(?:query|execute|prepare|raw)\s*\(\s*["'][^"']*["']\s*\+/g,
  /(?:query|execute|prepare|raw)\s*\([^)]*\+\s*["']/g,
  /(?:execute|cursor\.execute|\.query)\s*\(\s*f["']/g,
  // Direct variable pass-through (.query(sql) without a string literal)
  /\.query\s*\(\s*(?!["'`])[a-zA-Z_]\w*\s*[,)]/g,
];

const SQL_CONCAT_PY = [
  /(?:execute|cursor\.execute)\s*\(\s*f["']/g,
  /(?:execute|cursor\.execute)\s*\(\s*["'][^"']*["']\s*%/g,
  /(?:execute|cursor\.execute)\s*\(\s*["'][^"']*["']\s*\.\s*format/g,
  /(?:execute|cursor\.execute)\s*\(\s*["'][^"']*["']\s*\+/g,
  // Direct variable pass-through (cursor.execute(sql) without a string literal)
  /(?:cursor\.execute|\.execute)\s*\(\s*(?!["'f])[a-zA-Z_]\w*\s*[,)]/g,
];

// File operation patterns without validation
const PATH_TRAVERSAL_TS = [
  /\bfs\.readFile(?:Sync)?\s*\(/g,
  /\bfs\.writeFile(?:Sync)?\s*\(/g,
  /\bfs\.readdir(?:Sync)?\s*\(/g,
  /\bfs\.unlink(?:Sync)?\s*\(/g,
  /\bfs\.mkdir(?:Sync)?\s*\(/g,
  /\bfs\.access(?:Sync)?\s*\(/g,
];

const PATH_TRAVERSAL_PY = [
  /\bopen\s*\(/g,
  /\bos\.path\.\w+\s*\(/g,
  /\bshutil\.\w+\s*\(/g,
  /\bpathlib\.Path\s*\(/g,
];

// Path validation patterns (if present, the file op is probably safe)
const PATH_SAFE_PATTERNS = [
  /realpath/,
  /resolve\s*\(/,
  /startsWith\s*\(/,
  /startswith\s*\(/,
  /ALLOWED/i,
  /allowlist/i,
  /whitelist/i,
  /base_dir/i,
  /root_dir/i,
  /prefix.*check/i,
  /validate[_-]?path/i,
  /check[_-]?path/i,
  /sanitize[_-]?path/i,
  /safe[_-]?path/i,
  /allowed[_-]?paths/i,
];

function hasPathValidation(content: string, matchIndex: number): boolean {
  const start = Math.max(0, matchIndex - 500);
  const end = Math.min(content.length, matchIndex + 500);
  const context = content.slice(start, end);

  return PATH_SAFE_PATTERNS.some((p) => p.test(context));
}

export function detectCommandInjection(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];
  const patterns =
    context.language === "python" ? EXEC_PATTERNS_PY :
    context.language === "typescript" ? EXEC_PATTERNS_TS :
    [...EXEC_PATTERNS_TS, ...EXEC_PATTERNS_PY];

  for (const [file, content] of context.sources) {
    // Skip non-server files (scripts, CLI, tests, etc.)
    if (shouldSkipFile(file)) continue;

    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        // Skip if using execFile (safe — no shell)
        if (/execFile/.test(lineContent)) continue;

        // Skip if using shell: false explicitly
        if (/shell\s*:\s*false/.test(lineContent)) continue;

        // Skip if it's just an import/require or promisify setup line
        if (/\bimport\b/.test(lineContent) || /\brequire\b/.test(lineContent)) continue;
        if (/\bpromisify\s*\(\s*exec\s*\)/.test(lineContent)) continue;

        // Only flag if in a tool handler context
        if (!isInToolHandler(content, match.index, context.language)) continue;

        findings.push({
          ruleId: "MCS-INJ-001",
          severity: "critical",
          title: "Command Injection via Tool Input",
          message: `Shell command execution pattern detected in tool handler context. If tool input reaches this call, it enables arbitrary command execution.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Use execFile() with an argument array instead of exec(). Allowlist permitted commands.",
            suggestion: "execFile('/usr/bin/cmd', [arg1, arg2])",
          },
        });
      }
    }
  }

  return findings;
}

export function detectSqlInjection(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];
  const patterns =
    context.language === "python" ? SQL_CONCAT_PY :
    context.language === "typescript" ? SQL_CONCAT_TS :
    [...SQL_CONCAT_TS, ...SQL_CONCAT_PY];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;

    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        // Only flag if in a tool handler context
        if (!isInToolHandler(content, match.index, context.language)) continue;

        findings.push({
          ruleId: "MCS-INJ-002",
          severity: "critical",
          title: "SQL Injection via Tool Input",
          message: `SQL query constructed using string interpolation or concatenation. Use parameterized queries ($1, ?, :param) instead.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Use parameterized queries instead of string concatenation.",
            suggestion: "db.query('SELECT * FROM users WHERE name = $1', [name])",
          },
        });
      }
    }
  }

  return findings;
}

export function detectPathTraversal(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];
  const patterns =
    context.language === "python" ? PATH_TRAVERSAL_PY :
    context.language === "typescript" ? PATH_TRAVERSAL_TS :
    [...PATH_TRAVERSAL_TS, ...PATH_TRAVERSAL_PY];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;

    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        if (isComment(lineContent)) continue;

        // Skip if there's path validation nearby
        if (hasPathValidation(content, match.index)) continue;

        // Only flag if we're in a tool handler context
        if (!isInToolHandler(content, match.index, context.language)) continue;

        findings.push({
          ruleId: "MCS-INJ-003",
          severity: "high",
          title: "Path Traversal in File Operations",
          message: `File operation without path validation. Tool input could access files outside the intended directory.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Resolve the path with realpath() and verify it starts with an allowed directory prefix.",
            suggestion: "const resolved = await fs.realpath(path.join(ALLOWED_DIR, input)); if (!resolved.startsWith(ALLOWED_DIR)) throw new Error('Access denied');",
          },
        });
      }
    }
  }

  return findings;
}
