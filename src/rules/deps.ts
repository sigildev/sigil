import type { AnalysisContext, Finding, Severity } from "../analyzers/types.js";

interface OsvVulnerability {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
}

interface OsvResponse {
  vulns?: OsvVulnerability[];
}

function mapOsvSeverity(vuln: OsvVulnerability): Severity {
  if (vuln.severity && vuln.severity.length > 0) {
    const score = parseFloat(vuln.severity[0].score);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }
  return "medium"; // default if no severity info
}

export async function detectVulnerableDeps(context: AnalysisContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (!context.manifest) return findings;

  const allDeps = {
    ...context.manifest.dependencies,
    ...context.manifest.devDependencies,
  };

  const ecosystem = context.language === "python" ? "PyPI" : "npm";

  for (const [name, versionSpec] of Object.entries(allDeps)) {
    // Clean version spec (remove ^, ~, >=, etc.)
    const version = versionSpec.replace(/^[\^~>=<]+/, "");
    if (!version || version === "*" || version === "latest") continue;

    try {
      const response = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          package: { name, ecosystem },
          version,
        }),
      });

      if (!response.ok) continue;

      const data = (await response.json()) as OsvResponse;
      if (data.vulns && data.vulns.length > 0) {
        for (const vuln of data.vulns) {
          findings.push({
            ruleId: "MCS-DEP-001",
            severity: mapOsvSeverity(vuln),
            title: "Known Vulnerable Dependency",
            message: `${name}@${version} has known vulnerability ${vuln.id}${vuln.summary ? `: ${vuln.summary}` : ""}`,
            location: {
              file: context.manifest.lockfilePath
                ? context.manifest.lockfilePath.split("/").pop() || "package.json"
                : "package.json",
              startLine: 1,
              endLine: 1,
            },
            fix: {
              description: `Update ${name} to a patched version.`,
            },
          });
        }
      }
    } catch {
      // Network error — skip this dep silently
      continue;
    }
  }

  return findings;
}
