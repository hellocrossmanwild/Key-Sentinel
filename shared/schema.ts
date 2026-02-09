import { z } from "zod";

// ─── Request Schemas ───────────────────────────────────────────────

export const scanRequestSchema = z.object({
  url: z.string().url("Please enter a valid URL"),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;

export const analyzeRequestSchema = z.object({
  keyType: z.string(),
  value: z.string(),
  file: z.string(),
  severity: z.string(),
  sourceUrl: z.string(),
});

export type AnalyzeRequest = z.infer<typeof analyzeRequestSchema>;

export const summaryRequestSchema = z.object({
  url: z.string(),
  scanType: z.string(),
  findingsCount: z.number(),
  criticalCount: z.number(),
  highCount: z.number(),
  mediumCount: z.number(),
  lowCount: z.number(),
  filesScanned: z.number(),
  headerScore: z.number().optional(),
  exposedPaths: z.number().optional(),
  sourceMapsFound: z.number().optional(),
  jwtTokensFound: z.number().optional(),
  securityScore: z.number().optional(),
  securityGrade: z.string().optional(),
  topFindings: z.array(z.object({
    keyType: z.string(),
    severity: z.string(),
    file: z.string(),
  })).optional(),
});

export type SummaryRequest = z.infer<typeof summaryRequestSchema>;

// ─── Core Finding Types ────────────────────────────────────────────

export interface KeyFinding {
  keyType: string;
  value: string;
  file: string;
  line?: number;
  severity: "critical" | "high" | "medium" | "low";
  source?: string; // "pattern" | "entropy" | "bundle" | "git-history"
}

// ─── Header Analysis ──────────────────────────────────────────────

export interface HeaderFinding {
  header: string;
  value?: string;
  status: "missing" | "present" | "insecure";
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  recommendation: string;
}

export interface HeaderAnalysisResult {
  url: string;
  statusCode: number;
  serverInfo?: string;
  findings: HeaderFinding[];
  score: number;
}

// ─── Sensitive Path Results ───────────────────────────────────────

export interface SensitivePathFinding {
  path: string;
  url: string;
  statusCode: number;
  contentType: string;
  contentLength: number;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  description: string;
  contentSnippet?: string;
}

export interface SensitivePathResult {
  pathsChecked: number;
  pathsFound: SensitivePathFinding[];
}

// ─── Source Map Results ───────────────────────────────────────────

export interface SourceMapFile {
  mapUrl: string;
  originalFiles: string[];
  totalOriginalFiles: number;
  contentSize: number;
}

export interface SourceMapResult {
  mapsFound: number;
  mapsScanned: number;
  exposedFiles: SourceMapFile[];
}

// ─── JWT Results ──────────────────────────────────────────────────

export interface JWTFinding {
  token: string;
  header: Record<string, any>;
  payload: Record<string, any>;
  isExpired: boolean;
  expiresAt?: string;
  issuedAt?: string;
  issuer?: string;
  hasUserData: boolean;
  file: string;
  line: number;
  severity: "critical" | "high" | "medium" | "low";
}

// ─── Security Score ───────────────────────────────────────────────

export interface SecurityScore {
  overall: number;
  grade: string;
  breakdown: {
    secrets: number;
    headers: number;
    exposedPaths: number;
    sourceMaps: number;
    jwtTokens: number;
  };
  summary: string;
}

// ─── AI Analysis ──────────────────────────────────────────────────

export interface AIAnalysis {
  service: string;
  description: string;
  implications: string[];
  accessScope: string;
  remediation: string[];
  riskLevel: string;
}

export interface AISummary {
  overallAssessment: string;
  attackScenario: string;
  prioritizedActions: string[];
  riskNarrative: string;
  complianceNotes: string;
}

// ─── Full Scan Result ─────────────────────────────────────────────

export interface ScanResult {
  id: string;
  url: string;
  scanType: "github" | "website";
  status: "scanning" | "complete" | "error";
  findings: KeyFinding[];
  filesScanned: number;
  scanDuration: number;
  error?: string;

  // New expanded results
  securityScore?: SecurityScore;
  headerAnalysis?: HeaderAnalysisResult;
  sensitivePathResult?: SensitivePathResult;
  sourceMapResult?: SourceMapResult;
  jwtFindings?: JWTFinding[];
  gitHistoryFindings?: KeyFinding[];

  // Scan metadata
  pagesScanned?: number;
  commitsScanned?: number;
}
