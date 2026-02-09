import { z } from "zod";

export const scanRequestSchema = z.object({
  url: z.string().url("Please enter a valid URL"),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;

export interface KeyFinding {
  keyType: string;
  value: string;
  file: string;
  line?: number;
  severity: "critical" | "high" | "medium" | "low";
}

export interface ScanResult {
  id: string;
  url: string;
  scanType: "github" | "website";
  status: "scanning" | "complete" | "error";
  findings: KeyFinding[];
  filesScanned: number;
  scanDuration: number;
  error?: string;
}
