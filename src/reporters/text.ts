import chalk, { Chalk, type ChalkInstance } from "chalk";
import type { ScanResult, Finding, Severity } from "../analyzers/types.js";

export interface TextFormatOptions {
  color?: boolean;
  quiet?: boolean;
}

export function formatText(
  result: ScanResult,
  options: TextFormatOptions = {}
): string {
  const { color = true, quiet = false } = options;
  const c = color ? chalk : new Chalk({ level: 0 });
  const lines: string[] = [];

  // ─── Banner ───
  if (!quiet) {
    lines.push("");
    lines.push(c.dim(`  Sigil v${result.scanner.version}`));
    lines.push("");
    lines.push(
      `  Scanning: ${c.bold(result.target.path)}`
    );
    lines.push(
      `  Language: ${result.target.language}` +
        (result.target.name ? ` (${result.target.name})` : "")
    );
    lines.push(
      `  Tools: ${result.server.tools.length} detected` +
        ` | Resources: ${result.server.resources.length} detected` +
        ` | Prompts: ${result.server.prompts.length} detected`
    );
    lines.push("");
  }

  // ─── Findings ───
  if (result.findings.length === 0) {
    lines.push(c.green("  No security findings detected."));
    lines.push("");
  } else {
    for (const finding of result.findings) {
      lines.push(formatFinding(finding, c));
      lines.push("");
    }
  }

  // ─── Summary ───
  if (!quiet) {
    const sep = c.dim("  " + "─".repeat(50));
    lines.push(sep);

    const counts = countBySeverity(result.findings);
    const countParts: string[] = [];
    if (counts.critical > 0)
      countParts.push(c.red.bold(`${counts.critical} critical`));
    if (counts.high > 0) countParts.push(c.yellow(`${counts.high} high`));
    if (counts.medium > 0) countParts.push(c.blue(`${counts.medium} medium`));
    if (counts.low > 0) countParts.push(c.dim(`${counts.low} low`));

    const total = result.findings.length;
    lines.push(
      `  ${total} finding${total !== 1 ? "s" : ""}: ${countParts.join(", ")}`
    );

    const scoreColor =
      result.score.label === "PASS"
        ? c.green
        : result.score.label === "WARN"
          ? c.yellow
          : c.red;
    lines.push(
      `  Trust Score: ${scoreColor.bold(`${result.score.value}/100`)} (${scoreColor(result.score.label)})`
    );
    lines.push(sep);
    lines.push("");
  }

  return lines.join("\n");
}

function formatFinding(finding: Finding, c: ChalkInstance): string {
  const badge = severityBadge(finding.severity, c);
  const lines: string[] = [];

  lines.push(`  ${badge}  ${c.bold(finding.ruleId)}  ${finding.title}`);
  lines.push(
    c.dim(`  │ `) + `${finding.location.file}:${finding.location.startLine}`
  );
  lines.push(c.dim(`  │ `) + finding.message);

  return lines.join("\n");
}

function severityBadge(severity: Severity, c: ChalkInstance): string {
  switch (severity) {
    case "critical":
      return c.bgRed.white.bold(` CRITICAL `);
    case "high":
      return c.bgYellow.black.bold(` HIGH `);
    case "medium":
      return c.bgBlue.white(` MEDIUM `);
    case "low":
      return c.dim(` LOW `);
  }
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of findings) {
    counts[f.severity]++;
  }
  return counts;
}
