import type { AnalysisContext, Finding } from "../analyzers/types.js";

const CREDENTIAL_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /["'`](sk-[a-zA-Z0-9_-]{20,})["'`]/g, label: "OpenAI API key" },
  { pattern: /["'`](sk-proj-[a-zA-Z0-9_-]{20,})["'`]/g, label: "OpenAI project key" },
  { pattern: /["'`](sk-ant-[a-zA-Z0-9_-]{20,})["'`]/g, label: "Anthropic API key" },
  { pattern: /["'`](ghp_[a-zA-Z0-9]{36,})["'`]/g, label: "GitHub personal access token" },
  { pattern: /["'`](gho_[a-zA-Z0-9]{36,})["'`]/g, label: "GitHub OAuth token" },
  { pattern: /["'`](github_pat_[a-zA-Z0-9_]{22,})["'`]/g, label: "GitHub PAT" },
  { pattern: /["'`](glpat-[a-zA-Z0-9_-]{20,})["'`]/g, label: "GitLab access token" },
  { pattern: /["'`](xoxb-[a-zA-Z0-9-]+)["'`]/g, label: "Slack bot token" },
  { pattern: /["'`](xoxp-[a-zA-Z0-9-]+)["'`]/g, label: "Slack user token" },
  { pattern: /["'`](AKIA[A-Z0-9]{16})["'`]/g, label: "AWS access key ID" },
  { pattern: /["'`](AIza[a-zA-Z0-9_-]{35})["'`]/g, label: "Google API key" },
  // Connection strings with embedded passwords
  { pattern: /["'`](mongodb(?:\+srv)?:\/\/[^"'`\s]*:[^"'`\s]*@[^"'`\s]+)["'`]/g, label: "MongoDB connection string with credentials" },
  { pattern: /["'`](postgres(?:ql)?:\/\/[^"'`\s]*:[^"'`\s]*@[^"'`\s]+)["'`]/g, label: "PostgreSQL connection string with credentials" },
  { pattern: /["'`](mysql:\/\/[^"'`\s]*:[^"'`\s]*@[^"'`\s]+)["'`]/g, label: "MySQL connection string with credentials" },
  { pattern: /["'`](redis:\/\/[^"'`\s]*:[^"'`\s]*@[^"'`\s]+)["'`]/g, label: "Redis connection string with credentials" },
  // Private keys
  { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, label: "Private key" },
];

function findLineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

export function detectHardcodedCredentials(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];

  for (const [file, content] of context.sources) {
    const lines = content.split("\n");

    for (const { pattern, label } of CREDENTIAL_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = findLineNumber(content, match.index);
        const line = lines[lineNumber - 1] || "";
        const trimmed = line.trimStart();

        // Skip comments
        if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

        // Skip env var references
        if (/process\.env|os\.environ|getenv|ENV\[/.test(line)) continue;

        findings.push({
          ruleId: "MCS-AUTH-001",
          severity: "critical",
          title: "Hardcoded Credentials",
          message: `${label} found hardcoded in source code. Use environment variables instead.`,
          location: { file, startLine: lineNumber, endLine: lineNumber },
          fix: {
            description: "Move the credential to an environment variable and reference it via process.env or os.environ.",
          },
        });
      }
    }
  }

  return findings;
}

export function detectSecretsInConfig(context: AnalysisContext): Finding[] {
  const findings: Finding[] = [];
  if (!context.configEntries) return findings;

  for (const entry of context.configEntries) {
    if (!entry.env) continue;
    for (const [key, value] of Object.entries(entry.env)) {
      const looksLikeSecret =
        /key|token|secret|password|credential|auth/i.test(key) &&
        !value.startsWith("$") &&
        !value.startsWith("${") &&
        value.length > 8;

      const isKnownKey = CREDENTIAL_PATTERNS.some((p) => {
        p.pattern.lastIndex = 0;
        return p.pattern.test(`"${value}"`);
      });

      if (looksLikeSecret || isKnownKey) {
        findings.push({
          ruleId: "MCS-AUTH-002",
          severity: "high",
          title: "Secrets in MCP Configuration",
          message: `MCP config for "${entry.name}" has a hardcoded secret in env var "${key}".`,
          location: { file: "mcp-config", startLine: 1, endLine: 1 },
          fix: {
            description: "Reference the secret from your shell environment instead of hardcoding it in the config file.",
          },
        });
      }
    }
  }

  return findings;
}
