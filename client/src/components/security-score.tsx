import type { SecurityScore } from "@shared/schema";
import { Card, CardContent } from "@/components/ui/card";
import { Shield, TrendingDown, TrendingUp } from "lucide-react";

function getGradeColor(grade: string): string {
  if (grade.startsWith("A")) return "text-green-600 dark:text-green-400";
  if (grade.startsWith("B")) return "text-blue-600 dark:text-blue-400";
  if (grade.startsWith("C")) return "text-yellow-600 dark:text-yellow-400";
  if (grade.startsWith("D")) return "text-orange-600 dark:text-orange-400";
  return "text-destructive";
}

function getScoreRingColor(score: number): string {
  if (score >= 90) return "stroke-green-500 dark:stroke-green-400";
  if (score >= 70) return "stroke-blue-500 dark:stroke-blue-400";
  if (score >= 50) return "stroke-yellow-500 dark:stroke-yellow-400";
  if (score >= 30) return "stroke-orange-500 dark:stroke-orange-400";
  return "stroke-destructive";
}

function getScoreBgColor(score: number): string {
  if (score >= 90) return "bg-green-500/10 dark:bg-green-500/15";
  if (score >= 70) return "bg-blue-500/10 dark:bg-blue-500/15";
  if (score >= 50) return "bg-yellow-500/10 dark:bg-yellow-500/15";
  if (score >= 30) return "bg-orange-500/10 dark:bg-orange-500/15";
  return "bg-destructive/10";
}

function ScoreRing({ score }: { score: number }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const ringColor = getScoreRingColor(score);

  return (
    <div className="relative w-36 h-36">
      <svg className="w-36 h-36 -rotate-90" viewBox="0 0 120 120">
        <circle
          cx="60" cy="60" r={radius}
          fill="none"
          strokeWidth="8"
          className="stroke-muted"
        />
        <circle
          cx="60" cy="60" r={radius}
          fill="none"
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={`${ringColor} transition-all duration-1000 ease-out`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-bold ${getGradeColor(score >= 90 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F")}`}>
          {score}
        </span>
        <span className="text-xs text-muted-foreground">/ 100</span>
      </div>
    </div>
  );
}

function BreakdownBar({ label, score }: { label: string; score: number }) {
  const bgColor = score >= 90 ? "bg-green-500" : score >= 70 ? "bg-blue-500" : score >= 50 ? "bg-yellow-500" : score >= 30 ? "bg-orange-500" : "bg-destructive";

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-medium">{score}/100</span>
      </div>
      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${bgColor}`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}

export function SecurityScoreCard({ score }: { score: SecurityScore }) {
  const isGood = score.overall >= 70;

  return (
    <Card className="overflow-hidden" data-testid="card-security-score">
      <CardContent className="p-6">
        <div className="flex items-start gap-6 flex-wrap">
          <div className="flex flex-col items-center gap-2">
            <ScoreRing score={score.overall} />
            <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-bold ${getScoreBgColor(score.overall)}`}>
              <Shield className="w-4 h-4" />
              <span className={getGradeColor(score.grade)}>Grade: {score.grade}</span>
            </div>
          </div>

          <div className="flex-1 min-w-[240px] space-y-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                {isGood ? (
                  <TrendingUp className="w-4 h-4 text-green-600 dark:text-green-400" />
                ) : (
                  <TrendingDown className="w-4 h-4 text-destructive" />
                )}
                <h3 className="font-semibold text-sm">Security Assessment</h3>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed" data-testid="text-score-summary">
                {score.summary}
              </p>
            </div>

            <div className="space-y-2.5">
              <BreakdownBar label="Secrets & Keys" score={score.breakdown.secrets} />
              <BreakdownBar label="HTTP Headers" score={score.breakdown.headers} />
              <BreakdownBar label="Exposed Paths" score={score.breakdown.exposedPaths} />
              <BreakdownBar label="Source Maps" score={score.breakdown.sourceMaps} />
              <BreakdownBar label="JWT Tokens" score={score.breakdown.jwtTokens} />
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
