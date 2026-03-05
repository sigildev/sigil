import type { AnalysisContext, Finding } from "./types.js";

/**
 * Dependency vulnerability checker.
 *
 * Parses lock files and queries the OSV.dev vulnerability database:
 * - package-lock.json / yarn.lock / pnpm-lock.yaml → extract dependency graph
 * - requirements.txt / poetry.lock / uv.lock → extract dependency list
 * - For each dependency + version, query https://api.osv.dev/v1/query
 *
 * TODO: Implement lock file parsing and OSV.dev queries
 */
export async function analyzeDependencies(
  _context: AnalysisContext
): Promise<Finding[]> {
  return [];
}
