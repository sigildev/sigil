import type { AnalysisContext, Finding } from "../types.js";

/**
 * TypeScript AST analyzer.
 *
 * Parses TypeScript/JavaScript source files using the TypeScript Compiler API
 * and runs rule-specific visitors to detect:
 * - MCP server instantiation (new McpServer(...), new Server(...))
 * - Tool registrations (.tool() calls) with name, description, schema, handler
 * - Resource registrations (.resource() calls)
 * - Dangerous sink usage in handlers (exec, eval, fs ops, SQL queries, fetch)
 *
 * TODO: Implement AST walking and taint tracking
 */
export function analyzeTypeScript(
  _context: AnalysisContext
): Finding[] {
  return [];
}
