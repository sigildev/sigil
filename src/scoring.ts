import type { Finding, Score, Severity, Grade, ScoreLabel } from "./analyzers/types.js";

const PENALTIES: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
};

export function computeScore(findings: Finding[]): Score {
  let totalPenalty = 0;
  for (const finding of findings) {
    totalPenalty += PENALTIES[finding.severity];
  }

  const value = Math.max(0, 100 - totalPenalty);
  const grade = computeGrade(value);
  const label = computeLabel(value);

  return { value, grade, label };
}

function computeGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}

function computeLabel(score: number): ScoreLabel {
  if (score >= 70) return "PASS";
  if (score >= 50) return "WARN";
  return "FAIL";
}
