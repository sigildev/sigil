import type { AnalysisContext, Finding } from "../types.js";

/**
 * Python AST analyzer.
 *
 * Parses Python source files using tree-sitter with the Python grammar
 * and runs rule-specific visitors to detect:
 * - FastMCP instantiation (FastMCP(...))
 * - Tool decorators (@mcp.tool(), @server.tool())
 * - Dangerous sink usage in decorated functions (os.system, subprocess.*, open(), eval(), exec())
 *
 * TODO: Implement tree-sitter parsing and taint tracking
 */
export function analyzePython(
  _context: AnalysisContext
): Finding[] {
  return [];
}
