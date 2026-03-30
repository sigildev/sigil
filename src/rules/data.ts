import type { AnalysisContext, Finding } from "../analyzers/types.js";
import {
  findLineNumber,
  isInToolHandler,
  shouldSkipFile,
  isComment,
} from "./utils.js";

// Patterns that expose entire environment
const ENV_EXPOSURE_TS = [
  /\bprocess\.env\b(?!\s*\.)(?!\s*\[)/g, // process.env without any key access (bare reference)
  /JSON\.stringify\s*\(\s*process\.env\b/g,
  /Object\.(?:keys|values|entries)\s*\(\s*process\.env\b/g,
];

const ENV_EXPOSURE_PY = [
  /\bos\.environ\b(?!\s*\.\s*get)(?!\s*\[)/g, // os.environ without .get() or []
  /dict\s*\(\s*os\.environ\b/g,
  /json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ/g,
];

export function detectEnvVarExposure(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];
  const patterns =
    context.language === "python" ? ENV_EXPOSURE_PY :
    context.language === "typescript" ? ENV_EXPOSURE_TS :
    [...ENV_EXPOSURE_TS, ...ENV_EXPOSURE_PY];

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
          ruleId: "MCS-DATA-001",
          severity: "high",
          title: "Environment Variable Exposure",
          message: `Entire process environment is accessed without filtering. This exposes API keys, credentials, and secrets to the LLM.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Access only specific environment variables by name, or filter out sensitive keys before returning.",
            suggestion: "const safeEnv = { NODE_ENV: process.env.NODE_ENV, PORT: process.env.PORT };",
          },
        });
      }
    }
  }

  return findings;
}

export function detectCredentialLeakage(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  // Patterns that return raw API responses without redaction
  const LEAK_PATTERNS = [
    /res\.(?:headers|data|body)\b/g,
    /response\.(?:headers|data|body)\b/g,
  ];

  // This rule is hard to detect well with regex alone — keep it conservative
  // Flag cases where raw HTTP response objects are returned in tool responses
  for (const [file, content] of context.sources) {
    if (shouldSkipFile(file)) continue;
    // Look for tool handlers that return raw response data
    const toolHandlerRegex = /\.tool\s*\([^)]*\)\s*[^{]*\{[\s\S]*?return\s*\{[\s\S]*?content/g;
    let handlerMatch;
    while ((handlerMatch = toolHandlerRegex.exec(content)) !== null) {
      const handlerText = handlerMatch[0];
      // Check if the handler returns raw response headers (may contain auth tokens)
      if (/headers/.test(handlerText) && /JSON\.stringify/.test(handlerText)) {
        // Skip if headers are only used for OUTGOING requests (setting auth, not leaking it)
        // Look for patterns like: headers: { Authorization, fetch(..., { headers, request.headers
        const outgoingPatterns = /(?:fetch|axios|request|httpx|requests)\s*\([^)]*headers|headers\s*[:=]\s*\{[^}]*(?:Authorization|Bearer|api.key|token)/i;
        const returnPatterns = /response\.headers|res\.headers|\.headers\b[^:=]/;
        const hasOutgoing = outgoingPatterns.test(handlerText);
        const hasReturnHeaders = returnPatterns.test(handlerText);

        // Only flag if response headers are returned, not just outgoing request headers
        if (hasOutgoing && !hasReturnHeaders) continue;

        const line = findLineNumber(content, handlerMatch.index);
        findings.push({
          ruleId: "MCS-DATA-002",
          severity: "high",
          title: "Credential Leakage in Tool Responses",
          message: `Tool handler may return raw HTTP response headers containing authentication tokens. Filter sensitive headers before returning.`,
          location: { file, startLine: line, endLine: line },
          fix: {
            description: "Redact authorization headers and other sensitive fields from API responses before returning to the LLM.",
          },
        });
      }
    }
  }

  return findings;
}
