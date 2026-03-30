/**
 * Shared utilities for security rules.
 */

/** Non-server files that should not produce findings. */
const SKIP_FILE_PATTERNS = [
  /\bscripts?\//i,
  /\brelease\.\w+$/i,
  /\bbuild\.\w+$/i,
  /\bgulpfile\./i,
  /\bwebpack\.\w+/i,
  /\brollup\.\w+/i,
  /\bvite\.config\./i,
  /\bvitest\.config\./i,
  /\best\.config\./i,
  /\bjest\.config\./i,
  /\btsconfig\./i,
  /\b\.smithery\//,
  /\b__tests__\//,
  /\b__mocks__\//,
  /\bfixtures?\//i,
  /\bexamples?\//i,
  /\bdocs?\//i,
  /\b\.github\//,
  /\bcli\//i,
  /\bbin\//i,
  /\btests?\//i,
  // Python test files
  /\btest_[^/]*\.py$/i,
  /\b[^/]*_test\.py$/i,
  /\bconftest\.py$/i,
  // TS/JS test files
  /\.(?:test|spec)\.[tj]sx?$/i,
  // Sandbox/container isolation (expected to run arbitrary code)
  /\bsandbox[-_]?container/i,
];

/**
 * Returns true if the file is unlikely to contain MCP tool handler code.
 * Used to skip build scripts, CLI utilities, test fixtures, etc.
 */
export function shouldSkipFile(filePath: string): boolean {
  return SKIP_FILE_PATTERNS.some((p) => p.test(filePath));
}

export function findLineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

/**
 * Checks if a match is within an MCP tool handler context.
 * Returns false (safe) by default — only flags code we're confident is in a handler.
 */
export function isInToolHandler(
  content: string,
  matchIndex: number,
  language: string
): boolean {
  const before = content.slice(Math.max(0, matchIndex - 3000), matchIndex);

  if (language === "typescript" || language === "unknown") {
    // Check for .tool( pattern — MCP SDK tool registration
    if (/\.tool\s*\(/g.test(before)) {
      const lastToolIndex = before.lastIndexOf(".tool(");
      if (lastToolIndex !== -1) {
        const afterTool = before.slice(lastToolIndex);
        const opens = (afterTool.match(/\{/g) || []).length;
        const closes = (afterTool.match(/\}/g) || []).length;
        if (opens > closes) return true;
      }
    }

    // Check for server.setRequestHandler — another MCP SDK pattern
    if (/setRequestHandler\s*\(/g.test(before)) {
      const lastHandler = before.lastIndexOf("setRequestHandler(");
      if (lastHandler !== -1) {
        const afterHandler = before.slice(lastHandler);
        const opens = (afterHandler.match(/\{/g) || []).length;
        const closes = (afterHandler.match(/\}/g) || []).length;
        if (opens > closes) return true;
      }
    }
  }

  if (language === "python" || language === "unknown") {
    // Check for @mcp.tool() or @server.tool() decorator
    if (/@\w+\.tool\s*\(/g.test(before)) return true;
    // Check for FastMCP tool function patterns
    if (/@\w+\.resource\s*\(/g.test(before)) return true;
  }

  // Not in a tool handler — don't flag
  return false;
}

/** Common test/placeholder credential values that shouldn't trigger alerts */
const PLACEHOLDER_PATTERNS = [
  /^test[-_]?/i,
  /^placeholder/i,
  /^example/i,
  /^dummy/i,
  /^fake/i,
  /^sample/i,
  /^your[-_]/i,
  /^xxx/i,
  /^changeme/i,
  /^TODO/i,
  /^REPLACE/i,
  /^insert[-_]/i,
  /^my[-_]?(?:api[-_]?)?key/i,
  /^<.*>$/,
  /^\$\{/,
  // Connection strings with placeholder credentials
  /:\/\/user(?:name)?:pass(?:word)?@/i,
  /:\/\/root:(?:root|password|pass|secret)@/i,
  /:\/\/admin:(?:admin|password|pass|secret)@/i,
  /:\/\/\w+:password@/i,
  /:\/\/[^:]+:[^@]+@example\.com/i,
];

/**
 * Returns true if the matched credential value looks like a test/placeholder.
 */
export function isPlaceholderCredential(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((p) => p.test(value));
}

/**
 * Detects if the server's primary purpose is code/command execution.
 * Such servers shouldn't be flagged for INJ-001 (command injection) or
 * PERM-003 (arbitrary code execution) since that's their intended function.
 */
const CODE_EXECUTOR_NAME_PATTERNS = [
  /\bbash\b/i,
  /\bshell\b/i,
  /\bterminal\b/i,
  /\brepl\b/i,
  /\bsandbox\b/i,
  /\bcode[-_]?runner\b/i,
  /\bcode[-_]?exec/i,
  /\binterpreter\b/i,
  /\bcommand[-_]?runner\b/i,
];

export function isCodeExecutorServer(context: {
  manifest?: { name?: string };
}): boolean {
  // Only match servers whose primary purpose (per package name) is code/command execution.
  // Individual exec tools in a multi-purpose server should still be flagged.
  const name = context.manifest?.name ?? "";
  return CODE_EXECUTOR_NAME_PATTERNS.some((p) => p.test(name));
}

export function isComment(line: string): boolean {
  const trimmed = line.trimStart();
  return (
    trimmed.startsWith("//") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("*") ||
    trimmed.startsWith("/*")
  );
}
