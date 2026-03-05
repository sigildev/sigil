import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { ManifestInfo } from "../analyzers/types.js";

/**
 * Parse package.json or pyproject.toml to extract manifest info.
 */
export async function parseManifest(
  rootDir: string
): Promise<ManifestInfo | undefined> {
  // Try package.json first
  try {
    const pkgPath = resolve(rootDir, "package.json");
    const raw = await readFile(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);

    // Check for lockfile
    let lockfilePath: string | undefined;
    for (const lockfile of [
      "package-lock.json",
      "yarn.lock",
      "pnpm-lock.yaml",
    ]) {
      try {
        const lp = resolve(rootDir, lockfile);
        await readFile(lp, "utf-8"); // just check it exists
        lockfilePath = lp;
        break;
      } catch {
        // try next
      }
    }

    return {
      name: pkg.name as string | undefined,
      version: pkg.version as string | undefined,
      dependencies: (pkg.dependencies as Record<string, string>) ?? {},
      devDependencies: (pkg.devDependencies as Record<string, string>) ?? {},
      lockfilePath,
    };
  } catch {
    // No package.json
  }

  // Try pyproject.toml
  try {
    const pyPath = resolve(rootDir, "pyproject.toml");
    const raw = await readFile(pyPath, "utf-8");

    // Basic TOML parsing for name/version — just regex for MVP
    const nameMatch = raw.match(/^name\s*=\s*"([^"]+)"/m);
    const versionMatch = raw.match(/^version\s*=\s*"([^"]+)"/m);

    // Extract dependencies from [project.dependencies] or [tool.poetry.dependencies]
    const deps: Record<string, string> = {};
    const depSection = raw.match(
      /\[(?:project\.)?dependencies\]\n([\s\S]*?)(?:\n\[|$)/
    );
    if (depSection) {
      const depLines = depSection[1].matchAll(/^(\S+)\s*=\s*"([^"]+)"/gm);
      for (const match of depLines) {
        deps[match[1]] = match[2];
      }
    }

    // Check for lockfile
    let lockfilePath: string | undefined;
    for (const lockfile of ["poetry.lock", "uv.lock"]) {
      try {
        const lp = resolve(rootDir, lockfile);
        await readFile(lp, "utf-8");
        lockfilePath = lp;
        break;
      } catch {
        // try next
      }
    }

    return {
      name: nameMatch?.[1],
      version: versionMatch?.[1],
      dependencies: deps,
      devDependencies: {},
      lockfilePath,
    };
  } catch {
    // No pyproject.toml
  }

  return undefined;
}
