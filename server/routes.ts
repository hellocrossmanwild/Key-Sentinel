import type { Express } from "express";
import { createServer, type Server } from "http";
import { performScan } from "./scanner";
import { scanRequestSchema, analyzeRequestSchema } from "@shared/schema";
import OpenAI from "openai";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  app.post("/api/scan", async (req, res) => {
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
        message: error.message || "Internal server error during scan.",
      });
    }
  });

  app.post("/api/analyze", async (req, res) => {
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

      const analysis = JSON.parse(content);
      return res.json(analysis);
    } catch (error: any) {
      console.error("Analysis error:", error);
      return res.status(500).json({
        message: error.message || "AI analysis failed.",
      });
    }
  });

  return httpServer;
}
