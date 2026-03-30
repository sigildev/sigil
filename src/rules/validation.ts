import type { AnalysisContext, Finding } from "../analyzers/types.js";
import { findLineNumber, shouldSkipFile } from "./utils.js";

export function detectMissingInputSchema(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;
    if (context.language === "typescript" || context.language === "unknown") {
      // Detect z.any() or z.unknown() in tool schemas — these accept anything without validation
      const weakTypeRegex = /z\.(?:any|unknown)\s*\(\)/g;
      let match;
      while ((match = weakTypeRegex.exec(content)) !== null) {
        const line = findLineNumber(content, match.index);
        const lineContent = content.split("\n")[line - 1] || "";

        const trimmed = lineContent.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#")) continue;

        // Only flag if this is within a .tool() registration context
        const before = content.slice(Math.max(0, match.index - 500), match.index);
        if (!/\.tool\s*\(/.test(before)) continue;

        findings.push({
          ruleId: "MCS-VALID-001",
          severity: "medium",
          title: "Missing Input Schema",
          message: `Tool registered with z.any() or z.unknown() — accepts any input without type or constraint checking.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Define input validation using specific Zod schemas to constrain what the LLM can pass to this tool.",
            suggestion: "{ query: z.string().max(100), limit: z.number().int().min(1).max(50) }",
          },
        });
      }
    }

    if (context.language === "python" || context.language === "unknown") {
      // Detect tool functions with untyped parameters (no type hint)
      // Pattern: @mcp.tool() decorated function with at least one param missing a type hint
      const pyToolFnRegex = /@\w+\.tool\s*\(\s*\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)/g;
      let match;
      while ((match = pyToolFnRegex.exec(content)) !== null) {
        const params = match[1];
        const paramList = params.split(",").map((p) => p.trim()).filter((p) => p.length > 0);
        if (paramList.length === 0) continue; // no-arg functions are fine

        // Skip self parameter (for class methods)
        const realParams = paramList.filter((p) => p !== "self");
        if (realParams.length === 0) continue;

        const allTyped = realParams.every((p) => p.includes(":"));
        if (allTyped) continue;

        const line = findLineNumber(content, match.index);

        findings.push({
          ruleId: "MCS-VALID-001",
          severity: "medium",
          title: "Missing Input Schema",
          message: `Tool function has untyped parameters. FastMCP uses type hints to generate input schemas — untyped params bypass validation.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Add type hints to all tool function parameters.",
          },
        });
      }
    }
  }

  return findings;
}
