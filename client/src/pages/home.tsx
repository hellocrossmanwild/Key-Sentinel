import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Shield, Search, AlertTriangle, Github, Globe, ArrowRight, Loader2, FileSearch, Clock, ShieldAlert, ShieldCheck, Copy, Check, Eye, EyeOff, Sparkles, ChevronDown, ChevronUp, Info, Wrench, Lock, Zap, History, Map, FolderOpen, Key } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { apiRequest } from "@/lib/queryClient";
import { scanRequestSchema, type ScanRequest, type ScanResult, type KeyFinding, type AIAnalysis } from "@shared/schema";
import { ThemeToggle } from "@/components/theme-toggle";
import { SecurityScoreCard } from "@/components/security-score";
import { HeaderFindings } from "@/components/header-findings";
import { PathFindings } from "@/components/path-findings";
import { ScanSummaryPanel } from "@/components/scan-summary";
import { ReportExportButton } from "@/components/report-export";

function SeverityBadge({ severity }: { severity: KeyFinding["severity"] }) {
  const variants: Record<string, string> = {
    critical: "bg-destructive text-destructive-foreground",
    high: "bg-primary text-primary-foreground",
    medium: "bg-secondary text-secondary-foreground",
    low: "bg-muted text-muted-foreground",
  };

  return (
    <Badge className={`${variants[severity]} text-xs uppercase tracking-wider font-semibold no-default-hover-elevate no-default-active-elevate`} data-testid={`badge-severity-${severity}`}>
      {severity}
    </Badge>
  );
}

function SourceBadge({ source }: { source?: string }) {
  if (!source || source === "pattern") return null;
  const labels: Record<string, string> = {
    entropy: "Entropy",
    bundle: "Bundle",
    "git-history": "Git History",
  };
  return (
    <Badge variant="outline" className="text-xs gap-1">
      {source === "git-history" && <History className="w-2.5 h-2.5" />}
      {source === "bundle" && <Key className="w-2.5 h-2.5" />}
      {labels[source] || source}
    </Badge>
  );
}

function AnalysisPanel({ analysis }: { analysis: AIAnalysis }) {
  return (
    <div className="mt-4 space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
      <div className="rounded-md bg-muted/50 p-4 space-y-4">
        <div className="flex items-start gap-3">
          <div className="p-1.5 rounded-md bg-primary/10 flex-shrink-0 mt-0.5">
            <Info className="w-3.5 h-3.5 text-primary" />
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Service</p>
            <p className="text-sm font-medium" data-testid="text-analysis-service">{analysis.service}</p>
            <p className="text-xs text-muted-foreground mt-1" data-testid="text-analysis-description">{analysis.description}</p>
          </div>
        </div>

        <div className="flex items-start gap-3">
          <div className="p-1.5 rounded-md bg-destructive/10 flex-shrink-0 mt-0.5">
            <ShieldAlert className="w-3.5 h-3.5 text-destructive" />
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Security Implications</p>
            <ul className="space-y-1" data-testid="list-implications">
              {analysis.implications.map((item, i) => (
                <li key={i} className="text-xs text-foreground flex items-start gap-2">
                  <span className="text-destructive mt-0.5 flex-shrink-0">-</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="flex items-start gap-3">
          <div className="p-1.5 rounded-md bg-primary/10 flex-shrink-0 mt-0.5">
            <Lock className="w-3.5 h-3.5 text-primary" />
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Access Scope</p>
            <p className="text-xs" data-testid="text-analysis-scope">{analysis.accessScope}</p>
          </div>
        </div>

        <div className="flex items-start gap-3">
          <div className="p-1.5 rounded-md bg-green-500/10 dark:bg-green-500/15 flex-shrink-0 mt-0.5">
            <Wrench className="w-3.5 h-3.5 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Remediation Steps</p>
            <ol className="space-y-1" data-testid="list-remediation">
              {analysis.remediation.map((step, i) => (
                <li key={i} className="text-xs text-foreground flex items-start gap-2">
                  <span className="text-green-600 dark:text-green-400 font-semibold mt-0.5 flex-shrink-0">{i + 1}.</span>
                  {step}
                </li>
              ))}
            </ol>
          </div>
        </div>

        <div className="flex items-start gap-3">
          <div className="p-1.5 rounded-md bg-primary/10 flex-shrink-0 mt-0.5">
            <Zap className="w-3.5 h-3.5 text-primary" />
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">Risk Assessment</p>
            <p className="text-xs" data-testid="text-analysis-risk">{analysis.riskLevel}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function FindingCard({ finding, index, sourceUrl }: { finding: KeyFinding; index: number; sourceUrl: string }) {
  const [copied, setCopied] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [showAnalysis, setShowAnalysis] = useState(false);

  const analyzeMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/analyze", {
        keyType: finding.keyType,
        value: finding.value,
        file: finding.file,
        severity: finding.severity,
        sourceUrl,
      });
      return await res.json() as AIAnalysis;
    },
    onSuccess: (data) => {
      setAnalysis(data);
      setShowAnalysis(true);
    },
  });

  const handleCopy = () => {
    navigator.clipboard.writeText(finding.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAnalyze = () => {
    if (analysis) {
      setShowAnalysis(!showAnalysis);
    } else {
      analyzeMutation.mutate();
    }
  };

  const maskValue = (val: string) => {
    if (val.length <= 8) return "*".repeat(val.length);
    return val.substring(0, 4) + "*".repeat(Math.min(val.length - 8, 20)) + val.substring(val.length - 4);
  };

  return (
    <Card className="transition-all duration-200" data-testid={`card-finding-${index}`}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <ShieldAlert className="w-4 h-4 text-destructive flex-shrink-0" />
            <span className="font-semibold text-sm" data-testid={`text-key-type-${index}`}>{finding.keyType}</span>
            <SeverityBadge severity={finding.severity} />
            <SourceBadge source={finding.source} />
          </div>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setRevealed(!revealed)}
              data-testid={`button-reveal-${index}`}
            >
              {revealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={handleCopy}
              data-testid={`button-copy-${index}`}
            >
              {copied ? <Check className="w-3.5 h-3.5 text-green-500 dark:text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            </Button>
          </div>
        </div>

        <div className="mt-3 rounded-md bg-muted p-3 font-mono text-xs break-all select-all" data-testid={`text-key-value-${index}`}>
          {revealed ? finding.value : maskValue(finding.value)}
        </div>

        <div className="mt-2 flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2 text-xs text-muted-foreground min-w-0">
            <FileSearch className="w-3 h-3 flex-shrink-0" />
            <span className="truncate" data-testid={`text-file-path-${index}`}>
              {finding.file}
              {finding.line ? `:${finding.line}` : ""}
            </span>
          </div>

          <Button
            variant={showAnalysis ? "secondary" : "outline"}
            size="sm"
            onClick={handleAnalyze}
            disabled={analyzeMutation.isPending}
            className="gap-1.5 text-xs flex-shrink-0"
            data-testid={`button-analyze-${index}`}
          >
            {analyzeMutation.isPending ? (
              <>
                <Loader2 className="w-3 h-3 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Sparkles className="w-3 h-3" />
                {analysis ? (showAnalysis ? "Hide Analysis" : "Show Analysis") : "AI Analysis"}
                {analysis && (showAnalysis ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)}
              </>
            )}
          </Button>
        </div>

        {analyzeMutation.isError && (
          <div className="mt-2 text-xs text-destructive flex items-center gap-1.5">
            <AlertTriangle className="w-3 h-3" />
            Analysis failed. Please try again.
          </div>
        )}

        {showAnalysis && analysis && <AnalysisPanel analysis={analysis} />}
      </CardContent>
    </Card>
  );
}

function JWTFindingCard({ finding, index }: { finding: any; index: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card className="transition-all duration-200">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <Key className="w-4 h-4 text-primary flex-shrink-0" />
            <span className="font-semibold text-sm">JWT Token</span>
            <SeverityBadge severity={finding.severity} />
            {finding.isExpired && <Badge variant="outline" className="text-xs">Expired</Badge>}
            {finding.hasUserData && <Badge variant="destructive" className="text-xs">Contains User Data</Badge>}
          </div>
          <Button variant="ghost" size="icon" onClick={() => setExpanded(!expanded)}>
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </Button>
        </div>

        <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
          <FileSearch className="w-3 h-3" />
          <span>{finding.file}:{finding.line}</span>
          {finding.issuer && <span>| Issuer: {finding.issuer}</span>}
          {finding.expiresAt && <span>| Expires: {new Date(finding.expiresAt).toLocaleDateString()}</span>}
        </div>

        {expanded && (
          <div className="mt-3 space-y-2 animate-in fade-in duration-200">
            <div className="rounded-md bg-muted p-3">
              <p className="text-xs font-semibold text-muted-foreground mb-1">Decoded Payload</p>
              <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                {JSON.stringify(finding.payload, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SourceMapFindings({ result }: { result: any }) {
  if (!result || result.mapsFound === 0) return null;

  return (
    <Card data-testid="card-source-maps">
      <CardContent className="p-5 space-y-3">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Map className="w-4 h-4 text-primary" />
            <h3 className="font-semibold text-sm">Source Map Exposure</h3>
          </div>
          <Badge variant="destructive" className="text-xs">
            {result.mapsFound} source map{result.mapsFound !== 1 ? "s" : ""} exposed
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground">
          Exposed source maps reveal your original unminified source code, file structure, and may contain hardcoded secrets.
        </p>
        {result.exposedFiles.map((file: any, i: number) => (
          <div key={i} className="p-2.5 rounded-md bg-muted/30 space-y-1">
            <code className="text-xs font-semibold break-all">{file.mapUrl}</code>
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span>{file.totalOriginalFiles} original files</span>
              <span>{(file.contentSize / 1024).toFixed(1)} KB</span>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function ScanResults({ result }: { result: ScanResult }) {
  const criticalCount = result.findings.filter(f => f.severity === "critical").length;
  const highCount = result.findings.filter(f => f.severity === "high").length;
  const mediumCount = result.findings.filter(f => f.severity === "medium").length;
  const lowCount = result.findings.filter(f => f.severity === "low").length;

  const isClean = result.findings.length === 0 &&
    (!result.sensitivePathResult || result.sensitivePathResult.pathsFound.length === 0) &&
    (!result.sourceMapResult || result.sourceMapResult.mapsFound === 0);

  const hasExtraFindings = result.headerAnalysis || result.sensitivePathResult?.pathsFound.length ||
    result.sourceMapResult?.mapsFound || result.jwtFindings?.length || result.gitHistoryFindings?.length;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Security Score */}
      {result.securityScore && (
        <SecurityScoreCard score={result.securityScore} />
      )}

      {/* Summary stats card */}
      <Card data-testid="card-scan-summary">
        <CardContent className="p-6">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="flex items-start gap-4">
              {isClean ? (
                <div className="p-3 rounded-md bg-green-500/10 dark:bg-green-500/15">
                  <ShieldCheck className="w-6 h-6 text-green-600 dark:text-green-400" />
                </div>
              ) : (
                <div className="p-3 rounded-md bg-destructive/10">
                  <ShieldAlert className="w-6 h-6 text-destructive" />
                </div>
              )}
              <div>
                <h3 className="font-semibold text-lg" data-testid="text-scan-title">
                  {isClean ? "No Exposed Keys Found" : `${result.findings.length} Exposed Key${result.findings.length > 1 ? "s" : ""} Found`}
                </h3>
                <p className="text-sm text-muted-foreground mt-1" data-testid="text-scan-url">
                  {result.url}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <ReportExportButton result={result} />
              <Badge variant="outline" className="gap-1">
                {result.scanType === "github" ? <Github className="w-3 h-3" /> : <Globe className="w-3 h-3" />}
                {result.scanType === "github" ? "GitHub" : "Website"}
              </Badge>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6">
            <div className="text-center p-3 rounded-md bg-muted/50">
              <div className="text-2xl font-bold" data-testid="text-files-scanned">{result.filesScanned}</div>
              <div className="text-xs text-muted-foreground mt-1">Files Scanned</div>
            </div>
            <div className="text-center p-3 rounded-md bg-muted/50">
              <div className="text-2xl font-bold" data-testid="text-findings-count">{result.findings.length}</div>
              <div className="text-xs text-muted-foreground mt-1">Findings</div>
            </div>
            <div className="text-center p-3 rounded-md bg-muted/50">
              <div className="text-2xl font-bold flex items-center justify-center gap-1">
                <Clock className="w-4 h-4 text-muted-foreground" />
                <span data-testid="text-scan-duration">{(result.scanDuration / 1000).toFixed(1)}s</span>
              </div>
              <div className="text-xs text-muted-foreground mt-1">Scan Time</div>
            </div>
            <div className="text-center p-3 rounded-md bg-muted/50">
              <div className="text-2xl font-bold" data-testid="text-severity-summary">
                {criticalCount > 0 ? (
                  <span className="text-destructive">{criticalCount} Critical</span>
                ) : highCount > 0 ? (
                  <span className="text-primary">{highCount} High</span>
                ) : mediumCount > 0 ? (
                  <span className="text-muted-foreground">{mediumCount} Med</span>
                ) : lowCount > 0 ? (
                  <span className="text-muted-foreground">{lowCount} Low</span>
                ) : (
                  <span className="text-green-600 dark:text-green-400">Clean</span>
                )}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Top Severity</div>
            </div>
          </div>

          {/* Extra scan metadata */}
          {(result.pagesScanned || result.commitsScanned) && (
            <div className="flex items-center gap-4 mt-4 text-xs text-muted-foreground">
              {result.pagesScanned && <span>Pages crawled: {result.pagesScanned}</span>}
              {result.commitsScanned && <span>Commits scanned: {result.commitsScanned}</span>}
              {result.sensitivePathResult && <span>Paths probed: {result.sensitivePathResult.pathsChecked}</span>}
              {result.sourceMapResult && result.sourceMapResult.mapsFound > 0 && (
                <span>Source maps: {result.sourceMapResult.mapsFound}</span>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* AI Summary */}
      <ScanSummaryPanel result={result} />

      {/* Tabbed results */}
      {hasExtraFindings ? (
        <Tabs defaultValue="secrets" className="space-y-4">
          <TabsList className="grid w-full grid-cols-2 sm:grid-cols-5 h-auto">
            <TabsTrigger value="secrets" className="gap-1.5 text-xs">
              <ShieldAlert className="w-3.5 h-3.5" />
              Secrets ({result.findings.length})
            </TabsTrigger>
            {result.headerAnalysis && (
              <TabsTrigger value="headers" className="gap-1.5 text-xs">
                <Globe className="w-3.5 h-3.5" />
                Headers
              </TabsTrigger>
            )}
            {result.sensitivePathResult && result.sensitivePathResult.pathsFound.length > 0 && (
              <TabsTrigger value="paths" className="gap-1.5 text-xs">
                <FolderOpen className="w-3.5 h-3.5" />
                Paths ({result.sensitivePathResult.pathsFound.length})
              </TabsTrigger>
            )}
            {((result.sourceMapResult && result.sourceMapResult.mapsFound > 0) || (result.jwtFindings && result.jwtFindings.length > 0)) && (
              <TabsTrigger value="advanced" className="gap-1.5 text-xs">
                <Key className="w-3.5 h-3.5" />
                Advanced
              </TabsTrigger>
            )}
            {result.gitHistoryFindings && result.gitHistoryFindings.length > 0 && (
              <TabsTrigger value="history" className="gap-1.5 text-xs">
                <History className="w-3.5 h-3.5" />
                Git History ({result.gitHistoryFindings.length})
              </TabsTrigger>
            )}
          </TabsList>

          <TabsContent value="secrets" className="space-y-3">
            {result.findings.length > 0 ? (
              <>
                <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider px-1">
                  Detected Exposures
                </h3>
                {result.findings.map((finding, index) => (
                  <FindingCard key={index} finding={finding} index={index} sourceUrl={result.url} />
                ))}
              </>
            ) : (
              <Card>
                <CardContent className="p-6 text-center">
                  <ShieldCheck className="w-8 h-8 text-green-600 dark:text-green-400 mx-auto mb-2" />
                  <p className="text-sm font-medium">No exposed secrets detected</p>
                  <p className="text-xs text-muted-foreground mt-1">Pattern and entropy scanning found no API keys or credentials.</p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {result.headerAnalysis && (
            <TabsContent value="headers">
              <HeaderFindings analysis={result.headerAnalysis} />
            </TabsContent>
          )}

          {result.sensitivePathResult && result.sensitivePathResult.pathsFound.length > 0 && (
            <TabsContent value="paths">
              <PathFindings result={result.sensitivePathResult} />
            </TabsContent>
          )}

          {((result.sourceMapResult && result.sourceMapResult.mapsFound > 0) || (result.jwtFindings && result.jwtFindings.length > 0)) && (
            <TabsContent value="advanced" className="space-y-4">
              {result.sourceMapResult && result.sourceMapResult.mapsFound > 0 && (
                <SourceMapFindings result={result.sourceMapResult} />
              )}
              {result.jwtFindings && result.jwtFindings.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider px-1">
                    JWT Tokens ({result.jwtFindings.length})
                  </h3>
                  {result.jwtFindings.map((jwt, i) => (
                    <JWTFindingCard key={i} finding={jwt} index={i} />
                  ))}
                </div>
              )}
            </TabsContent>
          )}

          {result.gitHistoryFindings && result.gitHistoryFindings.length > 0 && (
            <TabsContent value="history" className="space-y-3">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider px-1">
                Secrets Found in Git History
              </h3>
              <p className="text-xs text-muted-foreground px-1">
                These secrets were found in commit diffs — they may have been "deleted" but still live in git history.
              </p>
              {result.gitHistoryFindings.map((finding, index) => (
                <FindingCard key={index} finding={finding} index={1000 + index} sourceUrl={result.url} />
              ))}
            </TabsContent>
          )}
        </Tabs>
      ) : (
        /* No tabs needed — just show secrets list */
        result.findings.length > 0 && (
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider px-1">
              Detected Exposures
            </h3>
            {result.findings.map((finding, index) => (
              <FindingCard key={index} finding={finding} index={index} sourceUrl={result.url} />
            ))}
          </div>
        )
      )}
    </div>
  );
}

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanProgress, setScanProgress] = useState(0);

  const form = useForm<ScanRequest>({
    resolver: zodResolver(scanRequestSchema),
    defaultValues: {
      url: "",
    },
  });

  const urlValue = form.watch("url");
  const isGithubUrl = urlValue.includes("github.com");

  const scanMutation = useMutation({
    mutationFn: async (data: ScanRequest) => {
      setScanProgress(5);
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + Math.random() * 8;
        });
      }, 800);

      try {
        const res = await apiRequest("POST", "/api/scan", { url: data.url });
        clearInterval(progressInterval);
        setScanProgress(100);
        const responseData = await res.json();
        return responseData as ScanResult;
      } catch (error) {
        clearInterval(progressInterval);
        setScanProgress(0);
        throw error;
      }
    },
    onSuccess: (data) => {
      setResult(data);
      setTimeout(() => setScanProgress(0), 500);
    },
    onError: () => {
      setScanProgress(0);
    },
  });

  const handleScan = (data: ScanRequest) => {
    setResult(null);
    scanMutation.mutate(data);
  };

  const progressLabel = scanProgress < 15
    ? "Starting scan engines..."
    : scanProgress < 30
    ? "Crawling pages & fetching content..."
    : scanProgress < 45
    ? "Probing sensitive paths..."
    : scanProgress < 55
    ? "Analyzing HTTP headers..."
    : scanProgress < 65
    ? "Scanning for source maps..."
    : scanProgress < 75
    ? "Running 200+ pattern matchers..."
    : scanProgress < 85
    ? "Entropy analysis & JWT detection..."
    : scanProgress < 90
    ? "Calculating security score..."
    : "Finalizing results...";

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-md bg-primary/10">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <span className="font-semibold text-lg tracking-tight">KeyGuard</span>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="text-xs gap-1">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-green-500 dark:bg-green-400"></span>
              Scanner Active
            </Badge>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-8 sm:py-12 space-y-8">
        <div className="text-center space-y-3">
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">
            API Key Exposure Scanner
          </h1>
          <p className="text-muted-foreground max-w-xl mx-auto text-sm sm:text-base">
            Deep-scan any public URL for exposed secrets, API keys, credentials, and security misconfigurations with AI-powered analysis.
          </p>
        </div>

        <Card data-testid="card-scan-form">
          <CardContent className="p-4 sm:p-6">
            <Form {...form}>
              <form onSubmit={form.handleSubmit(handleScan)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="url"
                  render={({ field }) => (
                    <FormItem>
                      <FormControl>
                        <div className="relative">
                          <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none">
                            {isGithubUrl ? <Github className="w-4 h-4" /> : <Globe className="w-4 h-4" />}
                          </div>
                          <Input
                            type="url"
                            placeholder="https://github.com/user/repo or https://example.com"
                            className="pl-10 h-11"
                            data-testid="input-url"
                            {...field}
                          />
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
                    <span className="flex items-center gap-1.5">
                      <Search className="w-3.5 h-3.5" />
                      200+ patterns
                    </span>
                    <span className="flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5" />
                      Multi-page crawl
                    </span>
                    <span className="flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      Header & path analysis
                    </span>
                    <span className="flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5" />
                      AI analysis
                    </span>
                  </div>
                  <Button
                    type="submit"
                    disabled={scanMutation.isPending}
                    className="gap-2"
                    data-testid="button-scan"
                  >
                    {scanMutation.isPending ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4" />
                        Deep Scan
                        <ArrowRight className="w-3.5 h-3.5" />
                      </>
                    )}
                  </Button>
                </div>

                {scanMutation.isPending && scanProgress > 0 && (
                  <div className="space-y-2 animate-in fade-in duration-300">
                    <Progress value={scanProgress} className="h-1.5" data-testid="progress-scan" />
                    <p className="text-xs text-muted-foreground text-center">
                      {progressLabel}
                    </p>
                  </div>
                )}
              </form>
            </Form>
          </CardContent>
        </Card>

        {scanMutation.isError && (
          <Card data-testid="card-scan-error">
            <CardContent className="p-4 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-sm">Scan Failed</p>
                <p className="text-sm text-muted-foreground mt-1">
                  {scanMutation.error?.message || "Unable to scan the provided URL. Please check the URL and try again."}
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {result && <ScanResults result={result} />}

        {!result && !scanMutation.isPending && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card className="hover-elevate" data-testid="card-feature-patterns">
              <CardContent className="p-5 text-center space-y-3">
                <div className="mx-auto w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Search className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold text-sm">200+ Key Patterns</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Detects AWS, Stripe, OpenAI, Azure, GCP, GitHub, and 200+ more API key formats with entropy analysis.
                </p>
              </CardContent>
            </Card>
            <Card className="hover-elevate" data-testid="card-feature-deep">
              <CardContent className="p-5 text-center space-y-3">
                <div className="mx-auto w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold text-sm">Deep Scanning</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Multi-page crawling, source map detection, sensitive path probing, HTTP header analysis, and JS bundle inspection.
                </p>
              </CardContent>
            </Card>
            <Card className="hover-elevate" data-testid="card-feature-github">
              <CardContent className="p-5 text-center space-y-3">
                <div className="mx-auto w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Github className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold text-sm">Git History Scan</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Scans commit history for secrets that were "deleted" but still live in git — up to 200 files per repo.
                </p>
              </CardContent>
            </Card>
            <Card className="hover-elevate" data-testid="card-feature-ai">
              <CardContent className="p-5 text-center space-y-3">
                <div className="mx-auto w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Sparkles className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold text-sm">AI Analysis & Reports</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Get AI-powered risk assessment, attack scenarios, remediation steps, and exportable security reports.
                </p>
              </CardContent>
            </Card>
          </div>
        )}

        <div className="text-center pb-8">
          <p className="text-xs text-muted-foreground">
            KeyGuard scans publicly accessible content only. No data is stored or retained.
          </p>
        </div>
      </main>
    </div>
  );
}
