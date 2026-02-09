import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { performScan } from "./scanner";
import { scanRequestSchema, analyzeRequestSchema, summaryRequestSchema } from "@shared/schema";
import OpenAI from "openai";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

function safeJsonParse(content: string): { data: any; error: string | null } {
  try {
    return { data: JSON.parse(content), error: null };
  } catch {
    const cleaned = content.replace(/```json\s*/g, "").replace(/```\s*/g, "").trim();
    try {
      return { data: JSON.parse(cleaned), error: null };
    } catch {
      return { data: null, error: "AI returned malformed response. Please try again." };
    }
  }
}

function sanitizeErrorMessage(error: any): string {
  if (!error) return "An unexpected error occurred.";
  const msg = error.message || String(error);
  if (msg.includes("API key") || msg.includes("auth") || msg.includes("OPENAI")) {
    return "AI service configuration error. Please try again later.";
  }
  if (msg.includes("rate limit") || msg.includes("429")) {
    return "AI service is temporarily busy. Please wait a moment and try again.";
  }
  if (msg.includes("timeout") || msg.includes("ETIMEDOUT") || msg.includes("ECONNREFUSED")) {
    return "AI service is currently unreachable. Please try again later.";
  }
  if (msg.includes("Unsupported parameter")) {
    return "AI service request error. Please try again.";
  }
  return "An unexpected error occurred. Please try again.";
}

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function rateLimit(windowMs: number, maxRequests: number) {
  return (req: Request, res: Response, next: Function) => {
    const ip = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    const entry = rateLimitStore.get(ip);

    if (!entry || now > entry.resetAt) {
      rateLimitStore.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }

    if (entry.count >= maxRequests) {
      return res.status(429).json({
        message: "Too many requests. Please wait before trying again.",
      });
    }

    entry.count++;
    return next();
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitStore) {
    if (now > entry.resetAt) {
      rateLimitStore.delete(ip);
    }
  }
}, 60_000);

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  const scanLimiter = rateLimit(60_000, 10);
  const analyzeLimiter = rateLimit(60_000, 30);
  const summaryLimiter = rateLimit(60_000, 10);

  // ─── Scan endpoint ─────────────────────────────────────────────

  app.post("/api/scan", scanLimiter, async (req, res) => {
    try {
      const parsed = scanRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Invalid URL. Please provide a valid URL.",
        });
      }

      const { url } = parsed.data;

      try {
        new URL(url);
      } catch {
        return res.status(400).json({
          message: "Invalid URL format.",
        });
      }

      const result = await performScan(url);

      if (result.status === "error") {
        return res.status(422).json({
          message: result.error || "Scan failed.",
        });
      }

      return res.json(result);
    } catch (error: any) {
      console.error("Scan error:", error);
      return res.status(500).json({
        message: "Scan failed due to an internal error. Please try again.",
      });
    }
  });

  // ─── Per-finding AI analysis ───────────────────────────────────

  app.post("/api/analyze", analyzeLimiter, async (req, res) => {
    try {
      const parsed = analyzeRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Invalid analysis request.",
        });
      }

      const { keyType, value, file, severity, sourceUrl } = parsed.data;

      const maskedValue = value.length > 8
        ? value.substring(0, 4) + "..." + value.substring(value.length - 4)
        : "***";

      const prompt = `You are a cybersecurity expert analyzing an exposed API key or secret found in publicly accessible code.

Key Type: ${keyType}
Masked Value: ${maskedValue}
Found in file: ${file}
Source URL: ${sourceUrl}
Severity: ${severity}

Analyze this finding and return a JSON object with exactly these fields:
{
  "service": "The specific service/platform this key belongs to (e.g., 'AWS IAM', 'Stripe Payments', 'OpenAI API')",
  "description": "A 1-2 sentence plain-language explanation of what this key is and what it does",
  "implications": ["List of 3-4 specific security risks if this key is exploited"],
  "accessScope": "What an attacker could access or do with this key (1-2 sentences)",
  "remediation": ["List of 3-4 specific steps to fix this exposure"],
  "riskLevel": "A brief risk assessment in context (1 sentence)"
}

Be specific and practical. Reference the actual service and real-world attack scenarios. Return ONLY the JSON object.`;

      const response = await openai.chat.completions.create({
        model: "gpt-5-mini",
        messages: [{ role: "user", content: prompt }],
        response_format: { type: "json_object" },
        max_completion_tokens: 1024,
      });

      const content = response.choices[0]?.message?.content;
      if (!content) {
        return res.status(500).json({ message: "AI analysis returned empty response." });
      }

      const { data: analysis, error } = safeJsonParse(content);
      if (error) {
        return res.status(502).json({ message: error });
      }

      return res.json(analysis);
    } catch (error: any) {
      console.error("Analysis error:", error);
      return res.status(500).json({
        message: sanitizeErrorMessage(error),
      });
    }
  });

  // ─── Holistic AI scan summary ──────────────────────────────────

  app.post("/api/summary", summaryLimiter, async (req, res) => {
    try {
      const parsed = summaryRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Invalid summary request.",
        });
      }

      const data = parsed.data;

      const findingsList = data.topFindings
        ?.map(f => `- ${f.keyType} (${f.severity}) in ${f.file}`)
        .join("\n") || "None";

      const prompt = `You are a senior cybersecurity analyst writing an executive security assessment for a scanned target.

Target URL: ${data.url}
Scan Type: ${data.scanType}
Security Score: ${data.securityScore ?? "N/A"}/100 (Grade: ${data.securityGrade ?? "N/A"})

Findings Summary:
- Total findings: ${data.findingsCount}
- Critical: ${data.criticalCount}
- High: ${data.highCount}
- Medium: ${data.mediumCount}
- Low: ${data.lowCount}
- Files scanned: ${data.filesScanned}
- HTTP header score: ${data.headerScore ?? "N/A"}/100
- Exposed sensitive paths: ${data.exposedPaths ?? 0}
- Source maps found: ${data.sourceMapsFound ?? 0}
- JWT tokens found: ${data.jwtTokensFound ?? 0}

Top Findings:
${findingsList}

Return a JSON object with exactly these fields:
{
  "overallAssessment": "A 2-3 sentence executive summary of the security posture. Be direct and specific about the risk level.",
  "attackScenario": "A realistic 2-3 sentence scenario describing how an attacker could chain these findings together to compromise the target. Reference specific finding types.",
  "prioritizedActions": ["5 specific, ordered remediation steps the team should take immediately, from most to least urgent"],
  "riskNarrative": "A 2-3 sentence business-impact assessment explaining what's at stake in non-technical terms (data breach, financial loss, regulatory penalties, etc.)",
  "complianceNotes": "A 1-2 sentence note on relevant compliance frameworks that may be violated (GDPR, SOC2, PCI-DSS, HIPAA, etc.) based on the types of secrets exposed"
}

Be specific, practical, and reference the actual findings. Do not be generic. Return ONLY the JSON object.`;

      const response = await openai.chat.completions.create({
        model: "gpt-5-mini",
        messages: [{ role: "user", content: prompt }],
        response_format: { type: "json_object" },
        max_completion_tokens: 1500,
      });

      const content = response.choices[0]?.message?.content;
      if (!content) {
        return res.status(500).json({ message: "AI summary returned empty response." });
      }

      const { data: summary, error } = safeJsonParse(content);
      if (error) {
        return res.status(502).json({ message: error });
      }

      return res.json(summary);
    } catch (error: any) {
      console.error("Summary error:", error);
      return res.status(500).json({
        message: sanitizeErrorMessage(error),
      });
    }
  });

  return httpServer;
}
