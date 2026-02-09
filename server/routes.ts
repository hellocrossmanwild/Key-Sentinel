import type { Express } from "express";
import { createServer, type Server } from "http";
import { performScan } from "./scanner";
import { scanRequestSchema } from "@shared/schema";
import { z } from "zod";

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

  return httpServer;
}
