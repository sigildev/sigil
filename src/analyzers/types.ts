// ─── Severity & Grading ───

export type Severity = "critical" | "high" | "medium" | "low";

export type Grade = "A" | "B" | "C" | "D" | "F";

export type ScoreLabel = "PASS" | "WARN" | "FAIL";

// ─── Findings ───

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  location: Location;
  tool?: ToolContext;
  fix?: Fix;
}

export interface Location {
  file: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

export interface ToolContext {
  name: string;
  description?: string;
}

export interface Fix {
  description: string;
  suggestion?: string;
}

// ─── MCP Server Primitives ───

export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  hasHandler: boolean;
}

export interface ResourceInfo {
  uri: string;
  name?: string;
  description?: string;
}

export interface PromptInfo {
  name: string;
  description?: string;
  arguments?: string[];
}

// ─── Score ───

export interface Score {
  value: number;
  grade: Grade;
  label: ScoreLabel;
}

// ─── Scan Result ───

export interface ScanResult {
  scanner: {
    name: string;
    version: string;
  };
  target: TargetInfo;
  server: ServerInfo;
  findings: Finding[];
  score: Score;
  timestamp: string;
  duration: number;
}

export interface TargetInfo {
  path: string;
  name?: string;
  version?: string;
  language: "typescript" | "python" | "unknown";
}

export interface ServerInfo {
  tools: ToolInfo[];
  resources: ResourceInfo[];
  prompts: PromptInfo[];
}

// ─── Rule Definition ───

export type RuleCategory =
  | "injection"
  | "permissions"
  | "data-exfiltration"
  | "validation"
  | "description"
  | "auth"
  | "config"
  | "dependencies";

export interface RuleDefinition {
  id: string;
  name: string;
  severity: Severity;
  category: RuleCategory;
  description: string;
  detect: (context: AnalysisContext) => Finding[];
}

// ─── Analysis Context ───

export interface AnalysisContext {
  /** Absolute path to the scan root */
  rootDir: string;
  /** Detected language */
  language: "typescript" | "python" | "unknown";
  /** All source file paths (relative to rootDir) */
  sourceFiles: string[];
  /** Raw source code keyed by relative path */
  sources: Map<string, string>;
  /** Discovered MCP server info */
  server: ServerInfo;
  /** Manifest info (package.json / pyproject.toml) */
  manifest?: ManifestInfo;
  /** MCP config entries, if scanned from a config file */
  configEntries?: ConfigEntry[];
}

export interface ManifestInfo {
  name?: string;
  version?: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  lockfilePath?: string;
}

export interface ConfigEntry {
  name: string;
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

// ─── Output Format ───

export type OutputFormat = "text" | "json" | "sarif";
