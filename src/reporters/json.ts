import type { ScanResult } from "../analyzers/types.js";

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
