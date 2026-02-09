import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import type { ScanResult, AISummary } from "@shared/schema";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { apiRequest } from "@/lib/queryClient";
import { Sparkles, Loader2, AlertTriangle, Target, ShieldAlert, ListChecks, FileText, Scale } from "lucide-react";

export function ScanSummaryPanel({ result }: { result: ScanResult }) {
  const [summary, setSummary] = useState<AISummary | null>(null);
  const [show, setShow] = useState(false);

  const criticalCount = result.findings.filter(f => f.severity === "critical").length;
  const highCount = result.findings.filter(f => f.severity === "high").length;
  const mediumCount = result.findings.filter(f => f.severity === "medium").length;
  const lowCount = result.findings.filter(f => f.severity === "low").length;

  const summaryMutation = useMutation({
    mutationFn: async () => {
      const topFindings = result.findings.slice(0, 10).map(f => ({
        keyType: f.keyType,
        severity: f.severity,
        file: f.file,
      }));

      const res = await apiRequest("POST", "/api/summary", {
        url: result.url,
        scanType: result.scanType,
        findingsCount: result.findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        filesScanned: result.filesScanned,
        headerScore: result.headerAnalysis?.score,
        exposedPaths: result.sensitivePathResult?.pathsFound.length,
        sourceMapsFound: result.sourceMapResult?.mapsFound,
        jwtTokensFound: result.jwtFindings?.length,
        securityScore: result.securityScore?.overall,
        securityGrade: result.securityScore?.grade,
        topFindings,
      });
      return await res.json() as AISummary;
    },
    onSuccess: (data) => {
      setSummary(data);
      setShow(true);
    },
  });

  const handleClick = () => {
    if (summary) {
      setShow(!show);
    } else {
      summaryMutation.mutate();
    }
  };

  if (result.findings.length === 0 && !result.sensitivePathResult?.pathsFound.length && !result.sourceMapResult?.mapsFound) {
    return null;
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider px-1">
          AI Security Assessment
        </h3>
        <Button
          variant={show ? "secondary" : "default"}
          size="sm"
          onClick={handleClick}
          disabled={summaryMutation.isPending}
          className="gap-1.5"
          data-testid="button-ai-summary"
        >
          {summaryMutation.isPending ? (
            <>
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Generating...
            </>
          ) : (
            <>
              <Sparkles className="w-3.5 h-3.5" />
              {summary ? (show ? "Hide Summary" : "Show Summary") : "Generate AI Summary"}
            </>
          )}
        </Button>
      </div>

      {summaryMutation.isError && (
        <Card>
          <CardContent className="p-3 flex items-center gap-2 text-xs text-destructive">
            <AlertTriangle className="w-3.5 h-3.5" />
            Failed to generate summary. Please try again.
          </CardContent>
        </Card>
      )}

      {show && summary && (
        <Card className="animate-in fade-in slide-in-from-top-2 duration-300" data-testid="card-ai-summary">
          <CardContent className="p-5 space-y-4">
            <div className="flex items-center gap-2 mb-1">
              <div className="p-1.5 rounded-md bg-primary/10">
                <Sparkles className="w-4 h-4 text-primary" />
              </div>
              <h3 className="font-semibold text-sm">Holistic Security Analysis</h3>
              <Badge variant="secondary" className="text-xs">AI-Powered</Badge>
            </div>

            <div className="space-y-4">
              <div className="flex items-start gap-3">
                <div className="p-1.5 rounded-md bg-primary/10 flex-shrink-0 mt-0.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-primary" />
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Overall Assessment</p>
                  <p className="text-sm leading-relaxed">{summary.overallAssessment}</p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className="p-1.5 rounded-md bg-destructive/10 flex-shrink-0 mt-0.5">
                  <Target className="w-3.5 h-3.5 text-destructive" />
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Attack Scenario</p>
                  <p className="text-sm leading-relaxed">{summary.attackScenario}</p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className="p-1.5 rounded-md bg-green-500/10 dark:bg-green-500/15 flex-shrink-0 mt-0.5">
                  <ListChecks className="w-3.5 h-3.5 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Prioritized Actions</p>
                  <ol className="space-y-1.5">
                    {summary.prioritizedActions.map((action, i) => (
                      <li key={i} className="text-sm flex items-start gap-2">
                        <span className="text-green-600 dark:text-green-400 font-bold mt-0.5 flex-shrink-0">{i + 1}.</span>
                        {action}
                      </li>
                    ))}
                  </ol>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className="p-1.5 rounded-md bg-primary/10 flex-shrink-0 mt-0.5">
                  <FileText className="w-3.5 h-3.5 text-primary" />
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Risk Narrative</p>
                  <p className="text-sm leading-relaxed">{summary.riskNarrative}</p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className="p-1.5 rounded-md bg-blue-500/10 flex-shrink-0 mt-0.5">
                  <Scale className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Compliance Notes</p>
                  <p className="text-sm leading-relaxed">{summary.complianceNotes}</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
