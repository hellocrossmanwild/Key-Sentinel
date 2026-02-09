import type { HeaderAnalysisResult, HeaderFinding } from "@shared/schema";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, ShieldAlert, ShieldX, Info, Server } from "lucide-react";

function StatusIcon({ status }: { status: HeaderFinding["status"] }) {
  switch (status) {
    case "missing":
      return <ShieldX className="w-3.5 h-3.5 text-destructive" />;
    case "insecure":
      return <ShieldAlert className="w-3.5 h-3.5 text-orange-500" />;
    case "present":
      return <ShieldCheck className="w-3.5 h-3.5 text-green-600 dark:text-green-400" />;
  }
}

function SeverityDot({ severity }: { severity: HeaderFinding["severity"] }) {
  const colors: Record<string, string> = {
    critical: "bg-destructive",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
    info: "bg-muted-foreground",
  };
  return <span className={`inline-block w-2 h-2 rounded-full ${colors[severity]}`} />;
}

export function HeaderFindings({ analysis }: { analysis: HeaderAnalysisResult }) {
  const securityHeaders = analysis.findings.filter(f => f.category === "Security");
  const infoLeaks = analysis.findings.filter(f => f.category === "Information Leak");
  const corsIssues = analysis.findings.filter(f => f.category === "CORS");
  const cacheIssues = analysis.findings.filter(f => f.category === "Cache");
  const otherFindings = analysis.findings.filter(
    f => !["Security", "Information Leak", "CORS", "Cache"].includes(f.category)
  );

  const sections = [
    { title: "Security Headers", items: securityHeaders, icon: ShieldAlert },
    { title: "Information Leakage", items: infoLeaks, icon: Info },
    { title: "CORS Configuration", items: corsIssues, icon: Server },
    { title: "Cache Security", items: cacheIssues, icon: Server },
    { title: "Other", items: otherFindings, icon: Info },
  ].filter(s => s.items.length > 0);

  return (
    <Card data-testid="card-header-analysis">
      <CardContent className="p-5 space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-primary" />
            <h3 className="font-semibold text-sm">HTTP Header Security</h3>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs">
              Score: {analysis.score}/100
            </Badge>
            {analysis.serverInfo && (
              <Badge variant="secondary" className="text-xs">
                {analysis.serverInfo}
              </Badge>
            )}
          </div>
        </div>

        {sections.map(({ title, items, icon: Icon }) => (
          <div key={title} className="space-y-2">
            <div className="flex items-center gap-1.5">
              <Icon className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{title}</span>
              <Badge variant="outline" className="text-xs px-1.5 py-0">
                {items.length}
              </Badge>
            </div>
            <div className="space-y-1">
              {items.map((finding, i) => (
                <div key={i} className="flex items-start gap-2 p-2 rounded-md bg-muted/30 text-xs">
                  <StatusIcon status={finding.status} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <code className="font-semibold">{finding.header}</code>
                      <SeverityDot severity={finding.severity} />
                      {finding.value && (
                        <span className="text-muted-foreground truncate max-w-[200px]">{finding.value}</span>
                      )}
                    </div>
                    <p className="text-muted-foreground mt-0.5">{finding.description}</p>
                    <p className="text-primary/80 mt-0.5">{finding.recommendation}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
