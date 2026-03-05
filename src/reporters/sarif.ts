import type { ScanResult, Severity } from "../analyzers/types.js";

interface SarifResult {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      rules: SarifRuleDescriptor[];
    };
  };
  results: SarifFinding[];
}

interface SarifRuleDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifFinding {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string };
      region: {
        startLine: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
    };
  }[];
}

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

export function formatSarif(result: ScanResult): string {
  // Collect unique rules
  const ruleMap = new Map<string, SarifRuleDescriptor>();
  for (const finding of result.findings) {
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId.replace(/[^a-zA-Z0-9]/g, ""),
        shortDescription: { text: finding.title },
        defaultConfiguration: {
          level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
        },
      });
    }
  }

  const sarif: SarifResult = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-scanner",
            version: result.scanner.version,
            rules: Array.from(ruleMap.values()),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          level: SEVERITY_TO_SARIF_LEVEL[f.severity],
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location.file },
                region: {
                  startLine: f.location.startLine,
                  startColumn: f.location.startColumn,
                  endLine: f.location.endLine,
                  endColumn: f.location.endColumn,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
