import { useState } from "react";
import type { ScanResult } from "@shared/schema";
import { Button } from "@/components/ui/button";
import { Download, Loader2, Check } from "lucide-react";

function generateReportHTML(result: ScanResult): string {
  const criticalCount = result.findings.filter(f => f.severity === "critical").length;
  const highCount = result.findings.filter(f => f.severity === "high").length;
  const mediumCount = result.findings.filter(f => f.severity === "medium").length;
  const lowCount = result.findings.filter(f => f.severity === "low").length;

  const severityColor = (s: string) => {
    switch (s) {
      case "critical": return "#dc2626";
      case "high": return "#ea580c";
      case "medium": return "#ca8a04";
      case "low": return "#2563eb";
      default: return "#6b7280";
    }
  };

  const maskValue = (val: string) => {
    if (val.length <= 8) return "*".repeat(val.length);
    return val.substring(0, 4) + "*".repeat(Math.min(val.length - 8, 16)) + val.substring(val.length - 4);
  };

  const scoreSection = result.securityScore ? `
    <div class="score-section">
      <div class="score-circle">
        <span class="score-value">${result.securityScore.overall}</span>
        <span class="score-grade">Grade: ${result.securityScore.grade}</span>
      </div>
      <p class="score-summary">${result.securityScore.summary}</p>
      <div class="breakdown">
        <div class="breakdown-item"><span>Secrets & Keys</span><span>${result.securityScore.breakdown.secrets}/100</span></div>
        <div class="breakdown-item"><span>HTTP Headers</span><span>${result.securityScore.breakdown.headers}/100</span></div>
        <div class="breakdown-item"><span>Exposed Paths</span><span>${result.securityScore.breakdown.exposedPaths}/100</span></div>
        <div class="breakdown-item"><span>Source Maps</span><span>${result.securityScore.breakdown.sourceMaps}/100</span></div>
        <div class="breakdown-item"><span>JWT Tokens</span><span>${result.securityScore.breakdown.jwtTokens}/100</span></div>
      </div>
    </div>
  ` : "";

  const headerSection = result.headerAnalysis ? `
    <h2>HTTP Header Security (Score: ${result.headerAnalysis.score}/100)</h2>
    <table>
      <tr><th>Header</th><th>Status</th><th>Severity</th><th>Description</th></tr>
      ${result.headerAnalysis.findings.map(f => `
        <tr>
          <td><code>${f.header}</code></td>
          <td>${f.status}</td>
          <td><span class="badge" style="background:${severityColor(f.severity)}">${f.severity}</span></td>
          <td>${f.description}</td>
        </tr>
      `).join("")}
    </table>
  ` : "";

  const pathSection = result.sensitivePathResult && result.sensitivePathResult.pathsFound.length > 0 ? `
    <h2>Sensitive Path Exposure (${result.sensitivePathResult.pathsFound.length} found)</h2>
    <table>
      <tr><th>Path</th><th>Status</th><th>Severity</th><th>Category</th><th>Description</th></tr>
      ${result.sensitivePathResult.pathsFound.map(p => `
        <tr>
          <td><code>${p.path}</code></td>
          <td>HTTP ${p.statusCode}</td>
          <td><span class="badge" style="background:${severityColor(p.severity)}">${p.severity}</span></td>
          <td>${p.category}</td>
          <td>${p.description}</td>
        </tr>
      `).join("")}
    </table>
  ` : "";

  const sourceMapSection = result.sourceMapResult && result.sourceMapResult.mapsFound > 0 ? `
    <h2>Source Map Exposure (${result.sourceMapResult.mapsFound} found)</h2>
    <table>
      <tr><th>Source Map URL</th><th>Original Files</th><th>Size</th></tr>
      ${result.sourceMapResult.exposedFiles.map(m => `
        <tr>
          <td><code>${m.mapUrl}</code></td>
          <td>${m.totalOriginalFiles} files</td>
          <td>${(m.contentSize / 1024).toFixed(1)} KB</td>
        </tr>
      `).join("")}
    </table>
  ` : "";

  const jwtSection = result.jwtFindings && result.jwtFindings.length > 0 ? `
    <h2>JWT Token Exposure (${result.jwtFindings.length} found)</h2>
    <table>
      <tr><th>File</th><th>Expired</th><th>Has User Data</th><th>Issuer</th><th>Severity</th></tr>
      ${result.jwtFindings.map(j => `
        <tr>
          <td><code>${j.file}:${j.line}</code></td>
          <td>${j.isExpired ? "Yes" : "No"}</td>
          <td>${j.hasUserData ? "Yes" : "No"}</td>
          <td>${j.issuer || "N/A"}</td>
          <td><span class="badge" style="background:${severityColor(j.severity)}">${j.severity}</span></td>
        </tr>
      `).join("")}
    </table>
  ` : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KeyGuard Security Report - ${result.url}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a1a; line-height: 1.6; padding: 40px; max-width: 1000px; margin: 0 auto; }
  h1 { font-size: 24px; margin-bottom: 8px; }
  h2 { font-size: 18px; margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; }
  .header { border-bottom: 3px solid #3b82f6; padding-bottom: 20px; margin-bottom: 24px; }
  .header small { color: #6b7280; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 20px 0; }
  .meta-item { background: #f9fafb; padding: 16px; border-radius: 8px; text-align: center; }
  .meta-item .value { font-size: 28px; font-weight: 700; }
  .meta-item .label { font-size: 12px; color: #6b7280; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
  th { background: #f9fafb; font-weight: 600; font-size: 11px; text-transform: uppercase; }
  code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
  .badge { color: white; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .score-section { text-align: center; margin: 24px 0; padding: 24px; background: #f9fafb; border-radius: 12px; }
  .score-circle { margin-bottom: 12px; }
  .score-value { font-size: 48px; font-weight: 800; }
  .score-grade { display: block; font-size: 16px; font-weight: 600; color: #6b7280; }
  .score-summary { color: #4b5563; margin-bottom: 16px; }
  .breakdown { max-width: 400px; margin: 0 auto; }
  .breakdown-item { display: flex; justify-content: space-between; padding: 4px 0; font-size: 13px; }
  .finding { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 16px; margin: 8px 0; }
  .finding-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .finding-value { margin-top: 8px; background: #f3f4f6; padding: 8px 12px; border-radius: 6px; font-family: monospace; font-size: 12px; word-break: break-all; }
  .finding-meta { margin-top: 6px; font-size: 12px; color: #6b7280; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb; text-align: center; font-size: 12px; color: #9ca3af; }
  @media print { body { padding: 20px; } }
</style>
</head>
<body>
  <div class="header">
    <h1>KeyGuard Security Report</h1>
    <small>Generated: ${new Date().toISOString().split("T")[0]} | URL: ${result.url} | Scan Type: ${result.scanType}</small>
  </div>

  ${scoreSection}

  <div class="meta">
    <div class="meta-item">
      <div class="value">${result.filesScanned}</div>
      <div class="label">Files Scanned</div>
    </div>
    <div class="meta-item">
      <div class="value">${result.findings.length}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="meta-item">
      <div class="value" style="color:#dc2626">${criticalCount}</div>
      <div class="label">Critical</div>
    </div>
    <div class="meta-item">
      <div class="value" style="color:#ea580c">${highCount}</div>
      <div class="label">High</div>
    </div>
    <div class="meta-item">
      <div class="value" style="color:#ca8a04">${mediumCount}</div>
      <div class="label">Medium</div>
    </div>
    <div class="meta-item">
      <div class="value" style="color:#2563eb">${lowCount}</div>
      <div class="label">Low</div>
    </div>
  </div>

  ${result.findings.length > 0 ? `
    <h2>Secret & Key Findings (${result.findings.length})</h2>
    ${result.findings.map((f, i) => `
      <div class="finding">
        <div class="finding-header">
          <strong>${f.keyType}</strong>
          <span class="badge" style="background:${severityColor(f.severity)}">${f.severity}</span>
          ${f.source ? `<span class="badge" style="background:#6b7280">${f.source}</span>` : ""}
        </div>
        <div class="finding-value">${maskValue(f.value)}</div>
        <div class="finding-meta">${f.file}${f.line ? `:${f.line}` : ""}</div>
      </div>
    `).join("")}
  ` : "<h2>No Exposed Secrets Found</h2><p>No API keys, tokens, or credentials were detected.</p>"}

  ${headerSection}
  ${pathSection}
  ${sourceMapSection}
  ${jwtSection}

  <div class="footer">
    <p>KeyGuard Security Scanner | This report is for informational purposes only.</p>
    <p>Scan completed in ${(result.scanDuration / 1000).toFixed(1)}s</p>
  </div>
</body>
</html>`;
}

export function ReportExportButton({ result }: { result: ScanResult }) {
  const [exported, setExported] = useState(false);

  const handleExport = () => {
    const html = generateReportHTML(result);
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const domain = new URL(result.url).hostname.replace(/\./g, "-");
    a.download = `keyguard-report-${domain}-${new Date().toISOString().split("T")[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setExported(true);
    setTimeout(() => setExported(false), 3000);
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleExport}
      className="gap-1.5"
      data-testid="button-export-report"
    >
      {exported ? (
        <>
          <Check className="w-3.5 h-3.5 text-green-500" />
          Downloaded
        </>
      ) : (
        <>
          <Download className="w-3.5 h-3.5" />
          Export Report
        </>
      )}
    </Button>
  );
}
