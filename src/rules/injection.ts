import type { AnalysisContext, Finding } from "../analyzers/types.js";

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
  // Template literal with variable in SQL context
  /(?:query|execute|prepare|raw)\s*\(\s*`[^`]*\$\{/g,
  // String concatenation in SQL context
  /(?:query|execute|prepare|raw)\s*\(\s*["'][^"']*["']\s*\+/g,
  /(?:query|execute|prepare|raw)\s*\([^)]*\+\s*["']/g,
  // f-string SQL (Python)
  /(?:execute|cursor\.execute|\.query)\s*\(\s*f["']/g,
];

const SQL_CONCAT_PY = [
  /(?:execute|cursor\.execute)\s*\(\s*f["']/g,
  /(?:execute|cursor\.execute)\s*\(\s*["'][^"']*["']\s*%/g,
  /(?:execute|cursor\.execute)\s*\(\s*["'][^"']*["']\s*\.\s*format/g,
  /(?:execute|cursor\.execute)\s*\(\s*["'][^"']*["']\s*\+/g,
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
];

function findLineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function isInToolHandler(content: string, matchIndex: number, language: string): boolean {
  // Look backwards from the match for a tool registration pattern
  const before = content.slice(Math.max(0, matchIndex - 2000), matchIndex);

  if (language === "typescript" || language === "unknown") {
    // Check for .tool( pattern
    if (/\.tool\s*\(/g.test(before)) {
      // Make sure we're not past the end of that handler
      // Simple heuristic: count braces
      const lastToolIndex = before.lastIndexOf(".tool(");
      if (lastToolIndex !== -1) {
        const afterTool = before.slice(lastToolIndex);
        const opens = (afterTool.match(/\{/g) || []).length;
        const closes = (afterTool.match(/\}/g) || []).length;
        // If we haven't closed all the braces, we're still in the handler
        if (opens > closes) return true;
      }
    }
  }

  if (language === "python" || language === "unknown") {
    // Check for @mcp.tool() or @server.tool() decorator
    if (/@\w+\.tool\s*\(/g.test(before)) return true;
    if (/def\s+\w+.*->/.test(before)) return true;
  }

  // Fallback: if it's in a server file, consider it relevant
  return true;
}

function hasPathValidation(content: string, matchIndex: number): boolean {
  // Check surrounding context (200 chars before and after) for validation patterns
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
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        // Skip if it's a comment
        const trimmed = lineContent.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

        // Skip if using execFile (safe — no shell)
        if (/execFile/.test(lineContent)) continue;

        // Skip if using shell: false explicitly
        if (/shell\s*:\s*false/.test(lineContent)) continue;

        // Skip if it's just an import/require or promisify setup line
        if (/\bimport\b/.test(lineContent) || /\brequire\b/.test(lineContent)) continue;
        if (/\bpromisify\s*\(\s*exec\s*\)/.test(lineContent)) continue;

        findings.push({
          ruleId: "MCS-INJ-001",
          severity: "critical",
          title: "Command Injection via Tool Input",
          message: `Potential shell command execution found. If tool input reaches this call, it enables arbitrary command execution.`,
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
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        const trimmed = lineContent.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

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
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        const trimmed = lineContent.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

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
