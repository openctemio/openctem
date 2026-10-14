'use client'

import { useTranslation } from '@/context/i18n-provider'
import {
  epssScoreToPercent,
  formatEpssPercentile,
  formatEpssScore,
  formatEpssTopPercent,
} from '@/lib/epss'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { AlertTriangle, Shield, Network, Target } from 'lucide-react'

interface ThreatIntelCardProps {
  epssScore: number | null
  epssPercentile: number | null
  isInKev: boolean
  kevDueDate: string | null
  isReachable: boolean
  reachableFromCount: number
  priorityClass: string | null
  priorityClassReason: string | null
}

function formatDate(dateStr: string | null, t: (key: string, fallback?: string) => string): string {
  if (!dateStr) return t('findings.threatIntel.na', 'N/A')
  return new Date(dateStr).toLocaleDateString()
}

export function ThreatIntelCard({
  epssScore,
  epssPercentile,
  isInKev,
  kevDueDate,
  isReachable,
  reachableFromCount,
  priorityClass,
  priorityClassReason,
}: ThreatIntelCardProps) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Target className="h-4 w-4" />
          {t('findings.threatIntel.title', 'Threat Intelligence')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* EPSS Score */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">
              {t('findings.threatIntel.epssScore', 'EPSS Score')}
            </span>
            <span className="font-mono font-medium">
              {formatEpssScore(epssScore, 2, t('findings.threatIntel.na', 'N/A'))}
            </span>
          </div>
          {epssScore !== null && (
            <div className="h-2 w-full rounded-full bg-muted">
              <div
                className={cn(
                  'h-2 rounded-full transition-all',
                  epssScore >= 0.5
                    ? 'bg-red-500'
                    : epssScore >= 0.1
                      ? 'bg-orange-500'
                      : epssScore >= 0.01
                        ? 'bg-yellow-500'
                        : 'bg-green-500'
                )}
                style={{ width: `${epssScoreToPercent(epssScore)}%` }}
              />
            </div>
          )}
          {epssPercentile !== null && (
            <p className="text-xs text-muted-foreground">
              {t('findings.threatIntel.percentile', 'Percentile: {percentile} ({top})', {
                percentile: formatEpssPercentile(epssPercentile),
                top: formatEpssTopPercent(epssPercentile),
              })}
            </p>
          )}
        </div>

        {/* KEV Status */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm">
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">
              {t('findings.threatIntel.kev', 'Known Exploited (KEV)')}
            </span>
          </div>
          {isInKev ? (
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20">
                {t('findings.threatIntel.inKev', 'In KEV')}
              </Badge>
              {kevDueDate && (
                <span className="text-xs text-muted-foreground">
                  {t('findings.threatIntel.due', 'Due: {date}', {
                    date: formatDate(kevDueDate, t),
                  })}
                </span>
              )}
            </div>
          ) : (
            <Badge variant="outline" className="bg-muted text-muted-foreground">
              {t('findings.threatIntel.notInKev', 'Not in KEV')}
            </Badge>
          )}
        </div>

        {/* Reachability */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm">
            <Network className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">
              {t('findings.threatIntel.reachability', 'Reachability')}
            </span>
          </div>
          {isReachable ? (
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                className="bg-orange-500/10 text-orange-500 border-orange-500/20"
              >
                {t('findings.threatIntel.reachable', 'Reachable')}
              </Badge>
              {reachableFromCount > 0 && (
                <span className="text-xs text-muted-foreground">
                  {reachableFromCount === 1
                    ? t('findings.threatIntel.fromPathOne', 'from {count} path', {
                        count: reachableFromCount,
                      })
                    : t('findings.threatIntel.fromPathMany', 'from {count} paths', {
                        count: reachableFromCount,
                      })}
                </span>
              )}
            </div>
          ) : (
            <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/20">
              {t('findings.threatIntel.notReachable', 'Not Reachable')}
            </Badge>
          )}
        </div>

        {/* Priority Classification */}
        {priorityClass && (
          <div className="rounded-lg border p-3 space-y-1">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <span className="text-muted-foreground">
                  {t('findings.threatIntel.priorityClass', 'Priority Class')}
                </span>
              </div>
              <Badge
                variant="outline"
                className={cn(
                  priorityClass === 'P0'
                    ? 'bg-red-500/10 text-red-500 border-red-500/20'
                    : priorityClass === 'P1'
                      ? 'bg-orange-500/10 text-orange-500 border-orange-500/20'
                      : priorityClass === 'P2'
                        ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
                        : 'bg-blue-500/10 text-blue-500 border-blue-500/20',
                  'font-mono font-bold'
                )}
              >
                {priorityClass}
              </Badge>
            </div>
            {priorityClassReason && (
              <p className="text-xs text-muted-foreground">{priorityClassReason}</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
