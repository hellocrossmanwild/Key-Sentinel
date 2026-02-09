import type { KeyFinding, SensitivePathResult, HeaderAnalysisResult, SourceMapResult } from "@shared/schema";
import type { JWTFinding } from "./jwt-detector";

export interface SecurityScore {
  overall: number;         // 0-100
  grade: string;           // A+ through F
  breakdown: {
    secrets: number;       // 0-100 subscore
    headers: number;       // 0-100 subscore
    exposedPaths: number;  // 0-100 subscore
    sourceMaps: number;    // 0-100 subscore
    jwtTokens: number;     // 0-100 subscore
  };
  summary: string;         // One-line summary
}

interface ScoreInput {
  findings: KeyFinding[];
  headerAnalysis?: HeaderAnalysisResult;
  sensitivePathResult?: SensitivePathResult;
  sourceMapResult?: SourceMapResult;
  jwtFindings?: JWTFinding[];
}

function gradeFromScore(score: number): string {
  if (score >= 97) return "A+";
  if (score >= 93) return "A";
  if (score >= 90) return "A-";
  if (score >= 87) return "B+";
  if (score >= 83) return "B";
  if (score >= 80) return "B-";
  if (score >= 77) return "C+";
  if (score >= 73) return "C";
  if (score >= 70) return "C-";
  if (score >= 67) return "D+";
  if (score >= 63) return "D";
  if (score >= 60) return "D-";
  return "F";
}

function calculateSecretsScore(findings: KeyFinding[]): number {
  if (findings.length === 0) return 100;

  let deductions = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical": deductions += 25; break;
      case "high": deductions += 15; break;
      case "medium": deductions += 8; break;
      case "low": deductions += 3; break;
    }
  }
  return Math.max(0, 100 - deductions);
}

function calculateHeadersScore(headerAnalysis?: HeaderAnalysisResult): number {
  if (!headerAnalysis) return 100; // not applicable (e.g. GitHub scan)
  return headerAnalysis.score;
}

function calculatePathsScore(pathResult?: SensitivePathResult): number {
  if (!pathResult) return 100;
  if (pathResult.pathsFound.length === 0) return 100;

  let deductions = 0;
  for (const p of pathResult.pathsFound) {
    switch (p.severity) {
      case "critical": deductions += 30; break;
      case "high": deductions += 18; break;
      case "medium": deductions += 10; break;
      case "low": deductions += 4; break;
    }
  }
  return Math.max(0, 100 - deductions);
}

function calculateSourceMapsScore(sourceMapResult?: SourceMapResult): number {
  if (!sourceMapResult) return 100;
  if (sourceMapResult.mapsFound === 0) return 100;
  // Each exposed source map is a significant finding
  const deductions = sourceMapResult.mapsFound * 20;
  return Math.max(0, 100 - deductions);
}

function calculateJWTScore(jwtFindings?: JWTFinding[]): number {
  if (!jwtFindings || jwtFindings.length === 0) return 100;

  let deductions = 0;
  for (const j of jwtFindings) {
    switch (j.severity) {
      case "critical": deductions += 25; break;
      case "high": deductions += 15; break;
      case "medium": deductions += 8; break;
      case "low": deductions += 3; break;
    }
  }
  return Math.max(0, 100 - deductions);
}

function generateSummary(score: number, grade: string, input: ScoreInput): string {
  const criticalCount = input.findings.filter(f => f.severity === "critical").length;
  const highCount = input.findings.filter(f => f.severity === "high").length;
  const totalFindings = input.findings.length;
  const pathsExposed = input.sensitivePathResult?.pathsFound.length ?? 0;
  const mapsExposed = input.sourceMapResult?.mapsFound ?? 0;
  const jwtCount = input.jwtFindings?.length ?? 0;

  if (score >= 90) {
    if (totalFindings === 0 && pathsExposed === 0) {
      return "Excellent security posture. No exposed secrets or sensitive paths detected.";
    }
    return `Good security posture with ${totalFindings} minor finding${totalFindings !== 1 ? "s" : ""} to address.`;
  }

  if (score >= 70) {
    const issues: string[] = [];
    if (totalFindings > 0) issues.push(`${totalFindings} exposed secret${totalFindings !== 1 ? "s" : ""}`);
    if (pathsExposed > 0) issues.push(`${pathsExposed} sensitive path${pathsExposed !== 1 ? "s" : ""}`);
    if (mapsExposed > 0) issues.push(`${mapsExposed} source map${mapsExposed !== 1 ? "s" : ""}`);
    return `Moderate risk. Found ${issues.join(", ")}. Review and remediate.`;
  }

  if (score >= 50) {
    const issues: string[] = [];
    if (criticalCount > 0) issues.push(`${criticalCount} critical`);
    if (highCount > 0) issues.push(`${highCount} high-severity`);
    return `High risk. ${issues.join(" and ")} exposure${criticalCount + highCount !== 1 ? "s" : ""} detected. Immediate action required.`;
  }

  // score < 50
  const allIssues: string[] = [];
  if (criticalCount > 0) allIssues.push(`${criticalCount} critical secret${criticalCount !== 1 ? "s" : ""}`);
  if (pathsExposed > 0) allIssues.push(`${pathsExposed} exposed path${pathsExposed !== 1 ? "s" : ""}`);
  if (mapsExposed > 0) allIssues.push(`exposed source maps`);
  if (jwtCount > 0) allIssues.push(`${jwtCount} JWT token${jwtCount !== 1 ? "s" : ""}`);
  return `Critical risk level. ${allIssues.join(", ")} found. Immediate remediation essential.`;
}

export function calculateSecurityScore(input: ScoreInput): SecurityScore {
  const breakdown = {
    secrets: calculateSecretsScore(input.findings),
    headers: calculateHeadersScore(input.headerAnalysis),
    exposedPaths: calculatePathsScore(input.sensitivePathResult),
    sourceMaps: calculateSourceMapsScore(input.sourceMapResult),
    jwtTokens: calculateJWTScore(input.jwtFindings),
  };

  // Weighted average: secrets matter most
  const weights = {
    secrets: 0.40,
    headers: 0.15,
    exposedPaths: 0.20,
    sourceMaps: 0.15,
    jwtTokens: 0.10,
  };

  const overall = Math.round(
    breakdown.secrets * weights.secrets +
    breakdown.headers * weights.headers +
    breakdown.exposedPaths * weights.exposedPaths +
    breakdown.sourceMaps * weights.sourceMaps +
    breakdown.jwtTokens * weights.jwtTokens
  );

  const grade = gradeFromScore(overall);
  const summary = generateSummary(overall, grade, input);

  return { overall, grade, breakdown, summary };
}
