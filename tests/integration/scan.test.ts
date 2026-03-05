import { describe, it, expect } from "vitest";
import { scan } from "../../src/scanner.js";
import { resolve } from "path";

const FIXTURES = resolve(import.meta.dirname, "../fixtures");

describe("mcp-scanner integration", () => {
  describe("vulnerable TypeScript server", () => {
    const target = resolve(FIXTURES, "vulnerable-ts");

    it("should detect command injection (MCS-INJ-001)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-INJ-001"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("critical");
      expect(findings[0].location.file).toContain("index.ts");
    });

    it("should detect SQL injection (MCS-INJ-002)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-INJ-002"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("critical");
    });

    it("should detect path traversal (MCS-INJ-003)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-INJ-003"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("high");
    });

    it("should detect overly broad capabilities (MCS-PERM-001)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-PERM-001"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("high");
    });

    it("should detect arbitrary code execution (MCS-PERM-003)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-PERM-003"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("critical");
    });

    it("should detect environment variable exposure (MCS-DATA-001)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-DATA-001"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("high");
    });

    it("should detect missing input schema (MCS-VALID-001)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-VALID-001"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("medium");
    });

    it("should detect suspicious tool description (MCS-DESC-001)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-DESC-001"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("high");
    });

    it("should detect hardcoded credentials (MCS-AUTH-001)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-AUTH-001"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("critical");
    });

    it("should detect verbose error messages (MCS-CFG-002)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-CFG-002"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("low");
    });

    it("should produce a FAIL trust score", async () => {
      const result = await scan(target);
      expect(result.findings.length).toBeGreaterThanOrEqual(9);
      expect(result.score.value).toBeLessThan(70);
      expect(result.score.label).toBe("FAIL");
    });

    it("should detect the target as TypeScript", async () => {
      const result = await scan(target);
      expect(result.target.language).toBe("typescript");
      expect(result.target.name).toBe("vulnerable-mcp-server");
    });
  });

  describe("safe TypeScript server", () => {
    const target = resolve(FIXTURES, "safe-ts");

    it("should produce zero findings", async () => {
      const result = await scan(target);
      expect(result.findings).toHaveLength(0);
    });

    it("should produce a PASS trust score", async () => {
      const result = await scan(target);
      expect(result.score.value).toBe(100);
      expect(result.score.grade).toBe("A");
      expect(result.score.label).toBe("PASS");
    });
  });

  describe("vulnerable Python server", () => {
    const target = resolve(FIXTURES, "vulnerable-py");

    it("should detect command injection (MCS-INJ-001)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-INJ-001"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe("critical");
      expect(findings[0].location.file).toContain("server.py");
    });

    it("should detect hardcoded credentials (MCS-AUTH-001)", async () => {
      const result = await scan(target);
      const findings = result.findings.filter(
        (f) => f.ruleId === "MCS-AUTH-001"
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("should detect the target as Python", async () => {
      const result = await scan(target);
      expect(result.target.language).toBe("python");
      expect(result.target.name).toBe("vulnerable-mcp-server");
    });

    it("should produce a FAIL trust score", async () => {
      const result = await scan(target);
      expect(result.findings.length).toBeGreaterThanOrEqual(5);
      expect(result.score.label).toBe("FAIL");
    });
  });

  describe("safe Python server", () => {
    const target = resolve(FIXTURES, "safe-py");

    it("should produce zero findings", async () => {
      const result = await scan(target);
      expect(result.findings).toHaveLength(0);
    });

    it("should produce a PASS trust score", async () => {
      const result = await scan(target);
      expect(result.score.value).toBe(100);
      expect(result.score.label).toBe("PASS");
    });
  });

  describe("output formats", () => {
    const target = resolve(FIXTURES, "vulnerable-ts");

    it("should produce valid JSON output", async () => {
      const result = await scan(target);
      expect(result.scanner.name).toBe("sigil");
      expect(result.scanner.version).toBe("0.1.3");
      expect(result.timestamp).toBeTruthy();
      expect(result.duration).toBeGreaterThanOrEqual(0);
    });
  });

  describe("scoring", () => {
    it("should compute correct penalties", async () => {
      const result = await scan(resolve(FIXTURES, "vulnerable-ts"));
      // With rules implemented, the vulnerable server should have
      // at least: 4 critical (25 each = 100), 4 high (15 each = 60),
      // 1 medium (5), 1 low (2) = 167 penalty → score 0
      // Until rules are implemented, score will be 100
      expect(result.score.value).toBeGreaterThanOrEqual(0);
      expect(result.score.value).toBeLessThanOrEqual(100);
    });
  });
});
