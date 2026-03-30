import type { AnalysisContext, Finding } from "../analyzers/types.js";
import { shouldSkipFile } from "./utils.js";

// Prompt injection patterns in tool descriptions
const INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  // Override/ignore instructions — clearly malicious
  { pattern: /ignore\s+(?:previous|prior|above|all)\s+instructions/i, label: "Instruction override pattern" },
  { pattern: /disregard\s+(?:previous|prior|above|all)/i, label: "Instruction override pattern" },
  { pattern: /forget\s+(?:your|all)\s+(?:previous\s+)?instructions/i, label: "Instruction override pattern" },
  { pattern: /you\s+are\s+now\s+/i, label: "Role hijacking pattern" },
  { pattern: /new\s+instructions?\s*:/i, label: "Instruction injection pattern" },

  // Exfiltration patterns — clearly malicious
  { pattern: /~\/\.ssh/i, label: "SSH key exfiltration attempt" },
  { pattern: /\.env\b/i, label: "Environment file exfiltration attempt" },
  { pattern: /id_rsa/i, label: "SSH private key reference" },
  { pattern: /send\s+(?:the\s+)?(?:data|content|result|response|info|information)\s+to\s+https?:/i, label: "Data exfiltration to URL" },
  { pattern: /forward\s+(?:the\s+)?(?:data|content|result|response)\s+to\s+https?:/i, label: "Data forwarding to URL" },

  // Cross-tool manipulation — only flag with exfiltration or hidden action context
  { pattern: /before\s+returning.*(?:also|first)\s+(?:read|send|access)\s+/i, label: "Hidden pre-action instruction" },

  // Hidden content patterns — clearly malicious
  { pattern: /[\u200B\u200C\u200D\u2060\uFEFF]/, label: "Zero-width Unicode characters (hidden content)" },
];

// Find string literals that look like tool descriptions in source code
function extractDescriptionStrings(content: string, language: string): Array<{ text: string; line: number }> {
  const descriptions: Array<{ text: string; line: number }> = [];
  const lines = content.split("\n");

  if (language === "typescript" || language === "unknown") {
    // Pattern: server.tool("name", "description", ...)
    // The description is typically the second string argument
    const toolCallRegex = /\.tool\s*\(\s*["'`][^"'`]*["'`]\s*,\s*(["'`])([\s\S]*?)\1/g;
    let match;
    while ((match = toolCallRegex.exec(content)) !== null) {
      const desc = match[2];
      const line = content.slice(0, match.index).split("\n").length;
      descriptions.push({ text: desc, line });
    }

    // Also check multi-line template literals after tool name
    const templateRegex = /\.tool\s*\(\s*["'`][^"'`]*["'`]\s*,\s*`([^`]*)`/g;
    while ((match = templateRegex.exec(content)) !== null) {
      const desc = match[1];
      const line = content.slice(0, match.index).split("\n").length;
      descriptions.push({ text: desc, line });
    }
  }

  if (language === "python" || language === "unknown") {
    // Pattern: @mcp.tool() with docstring, or description parameter
    // FastMCP: @mcp.tool(description="...")
    const pyDescRegex = /description\s*=\s*["']([\s\S]*?)["']/g;
    let match;
    while ((match = pyDescRegex.exec(content)) !== null) {
      const desc = match[1];
      const line = content.slice(0, match.index).split("\n").length;
      descriptions.push({ text: desc, line });
    }

    // Also check docstrings after @mcp.tool() decorated functions
    const docstringRegex = /def\s+\w+[^:]*:\s*\n\s*"""([\s\S]*?)"""/g;
    while ((match = docstringRegex.exec(content)) !== null) {
      const desc = match[1];
      const line = content.slice(0, match.index).split("\n").length;
      descriptions.push({ text: desc, line });
    }
  }

  return descriptions;
}

export function detectSuspiciousDescriptions(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;
    const descriptions = extractDescriptionStrings(content, context.language);

    for (const { text, line } of descriptions) {
      for (const { pattern, label } of INJECTION_PATTERNS) {
        if (pattern.test(text)) {
          findings.push({
            ruleId: "MCS-DESC-001",
            severity: "high",
            title: "Suspicious Instructions in Tool Descriptions",
            message: `Tool description contains ${label}. This may be tool poisoning — hidden instructions processed by the LLM but not visible to users.`,
            location: { file, startLine: line, endLine: line },
            fix: {
              description: "Remove suspicious instructions from the tool description. Descriptions should only describe what the tool does, not instruct the model to take additional actions.",
            },
          });
          break; // One finding per description is enough
        }
      }
    }
  }

  return findings;
}
