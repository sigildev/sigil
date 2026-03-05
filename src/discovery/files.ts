import fg from "fast-glob";

const TS_PATTERNS = ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"];
const PY_PATTERNS = ["**/*.py"];

const IGNORE_PATTERNS = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/__pycache__/**",
  "**/.venv/**",
  "**/venv/**",
  "**/.git/**",
  "**/coverage/**",
  "**/*.test.ts",
  "**/*.test.js",
  "**/*.spec.ts",
  "**/*.spec.js",
  "**/test/**",
  "**/tests/**",
];

/**
 * Discover source files in the target directory based on detected language.
 * Returns paths relative to rootDir.
 */
export async function discoverFiles(
  rootDir: string,
  language: "typescript" | "python" | "unknown"
): Promise<string[]> {
  let patterns: string[];

  switch (language) {
    case "typescript":
      patterns = TS_PATTERNS;
      break;
    case "python":
      patterns = PY_PATTERNS;
      break;
    case "unknown":
      patterns = [...TS_PATTERNS, ...PY_PATTERNS];
      break;
  }

  return fg(patterns, {
    cwd: rootDir,
    ignore: IGNORE_PATTERNS,
    dot: false,
  });
}
