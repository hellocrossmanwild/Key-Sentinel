import type { SensitivePathResult, SensitivePathFinding } from "@shared/schema";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { FolderOpen, AlertTriangle, FileWarning, Database, Server, Cloud, Code } from "lucide-react";

const categoryIcons: Record<string, typeof FolderOpen> = {
  "Environment File": FileWarning,
  "Version Control": Code,
  "Config File": Server,
  "Debug Info": AlertTriangle,
  "Backup File": Database,
  "API Documentation": Code,
  "Cloud/CI Config": Cloud,
};

function SeverityBadge({ severity }: { severity: SensitivePathFinding["severity"] }) {
  const variants: Record<string, string> = {
    critical: "bg-destructive text-destructive-foreground",
    high: "bg-orange-600 text-white dark:bg-orange-500",
    medium: "bg-yellow-600 text-white dark:bg-yellow-500 dark:text-black",
    low: "bg-muted text-muted-foreground",
  };

  return (
    <Badge className={`${variants[severity]} text-xs uppercase tracking-wider font-semibold`}>
      {severity}
    </Badge>
  );
}

export function PathFindings({ result }: { result: SensitivePathResult }) {
  if (result.pathsFound.length === 0) return null;

  // Group by category
  const grouped = result.pathsFound.reduce<Record<string, SensitivePathFinding[]>>((acc, finding) => {
    const cat = finding.category;
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(finding);
    return acc;
  }, {});

  return (
    <Card data-testid="card-path-findings">
      <CardContent className="p-5 space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <FolderOpen className="w-4 h-4 text-primary" />
            <h3 className="font-semibold text-sm">Sensitive Path Exposure</h3>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs">
              {result.pathsChecked} paths checked
            </Badge>
            <Badge variant="destructive" className="text-xs">
              {result.pathsFound.length} exposed
            </Badge>
          </div>
        </div>

        {Object.entries(grouped).map(([category, findings]) => {
          const Icon = categoryIcons[category] || FolderOpen;
          return (
            <div key={category} className="space-y-2">
              <div className="flex items-center gap-1.5">
                <Icon className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {category}
                </span>
                <Badge variant="outline" className="text-xs px-1.5 py-0">
                  {findings.length}
                </Badge>
              </div>

              <div className="space-y-1.5">
                {findings.map((finding, i) => (
                  <div key={i} className="p-2.5 rounded-md bg-muted/30 space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <code className="text-xs font-semibold">{finding.path}</code>
                      <SeverityBadge severity={finding.severity} />
                      <Badge variant="outline" className="text-xs">
                        HTTP {finding.statusCode}
                      </Badge>
                      {finding.contentLength > 0 && (
                        <span className="text-xs text-muted-foreground">
                          {finding.contentLength > 1024
                            ? `${(finding.contentLength / 1024).toFixed(1)} KB`
                            : `${finding.contentLength} B`}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">{finding.description}</p>
                    {finding.contentSnippet && (
                      <div className="rounded bg-muted p-2 font-mono text-xs text-muted-foreground whitespace-pre-wrap break-all">
                        {finding.contentSnippet}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
