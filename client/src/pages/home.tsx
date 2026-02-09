import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Shield, Search, AlertTriangle, CheckCircle2, Github, Globe, ArrowRight, Loader2, FileSearch, Clock, ShieldAlert, ShieldCheck, Copy, Check, Eye, EyeOff } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { apiRequest } from "@/lib/queryClient";
import { scanRequestSchema, type ScanRequest, type ScanResult, type KeyFinding } from "@shared/schema";
import { ThemeToggle } from "@/components/theme-toggle";

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

function FindingCard({ finding, index }: { finding: KeyFinding; index: number }) {
  const [copied, setCopied] = useState(false);
  const [revealed, setRevealed] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(finding.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const maskValue = (val: string) => {
    if (val.length <= 8) return "*".repeat(val.length);
    return val.substring(0, 4) + "*".repeat(Math.min(val.length - 8, 20)) + val.substring(val.length - 4);
  };

  return (
    <Card className="hover-elevate transition-all duration-200" data-testid={`card-finding-${index}`}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <ShieldAlert className="w-4 h-4 text-destructive flex-shrink-0" />
            <span className="font-semibold text-sm" data-testid={`text-key-type-${index}`}>{finding.keyType}</span>
            <SeverityBadge severity={finding.severity} />
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

        <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
          <FileSearch className="w-3 h-3 flex-shrink-0" />
          <span className="truncate" data-testid={`text-file-path-${index}`}>
            {finding.file}
            {finding.line ? `:${finding.line}` : ""}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

function ScanResults({ result }: { result: ScanResult }) {
  const criticalCount = result.findings.filter(f => f.severity === "critical").length;
  const highCount = result.findings.filter(f => f.severity === "high").length;
  const mediumCount = result.findings.filter(f => f.severity === "medium").length;
  const lowCount = result.findings.filter(f => f.severity === "low").length;

  const isClean = result.findings.length === 0;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
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
        </CardContent>
      </Card>

      {result.findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider px-1">
            Detected Exposures
          </h3>
          {result.findings.map((finding, index) => (
            <FindingCard key={index} finding={finding} index={index} />
          ))}
        </div>
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
      setScanProgress(10);
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 85) {
            clearInterval(progressInterval);
            return 85;
          }
          return prev + Math.random() * 15;
        });
      }, 500);

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
            Enter a public GitHub repository URL or any public website URL to scan for exposed API keys, secrets, and credentials.
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
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1.5">
                      <Github className="w-3.5 h-3.5" />
                      Public repos
                    </span>
                    <span className="flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5" />
                      Public websites
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
                        Scan URL
                        <ArrowRight className="w-3.5 h-3.5" />
                      </>
                    )}
                  </Button>
                </div>

                {scanMutation.isPending && scanProgress > 0 && (
                  <div className="space-y-2 animate-in fade-in duration-300">
                    <Progress value={scanProgress} className="h-1.5" data-testid="progress-scan" />
                    <p className="text-xs text-muted-foreground text-center">
                      {scanProgress < 30 ? "Fetching content..." : scanProgress < 60 ? "Analyzing files for exposed keys..." : scanProgress < 85 ? "Running pattern matching..." : "Finalizing results..."}
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
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Card className="hover-elevate" data-testid="card-feature-patterns">
              <CardContent className="p-5 text-center space-y-3">
                <div className="mx-auto w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Search className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold text-sm">30+ Key Patterns</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Detects AWS, Stripe, OpenAI, Firebase, GitHub tokens, and many more common API key formats.
                </p>
              </CardContent>
            </Card>
            <Card className="hover-elevate" data-testid="card-feature-github">
              <CardContent className="p-5 text-center space-y-3">
                <div className="mx-auto w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Github className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold text-sm">GitHub Repos</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Scans all files in public repositories including config files, source code, and environment files.
                </p>
              </CardContent>
            </Card>
            <Card className="hover-elevate" data-testid="card-feature-web">
              <CardContent className="p-5 text-center space-y-3">
                <div className="mx-auto w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold text-sm">Website Scanning</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Fetches and analyzes page source, inline scripts, and linked JavaScript files for exposed secrets.
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
