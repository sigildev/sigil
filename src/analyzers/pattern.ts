import type { AnalysisContext, Finding } from "./types.js";

/**
 * Regex-based pattern matcher for rules that don't need AST understanding:
 * - Credential patterns (MCS-AUTH-001): high-entropy strings, known key prefixes
 * - Tool description analysis (MCS-DESC-001): prompt injection patterns
 * - Debug/config patterns (MCS-CFG-001, MCS-CFG-002)
 * - Transport config (MCS-CFG-003)
 *
 * TODO: Implement pattern matching
 */
export function analyzePatterns(
  _context: AnalysisContext
): Finding[] {
  return [];
}
