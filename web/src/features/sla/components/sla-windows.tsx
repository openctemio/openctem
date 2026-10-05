'use client'

import { Timer } from 'lucide-react'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'

import { useAssetSlaPolicyApi, type SlaPolicy } from '../api/use-sla-policies-api'
import { DEFAULT_SLA_FORM } from '../schemas/sla-policy-schema'

/** The windows a policy (or the platform default) sets, in days. */
export type SlaWindowValues = Pick<
  SlaPolicy,
  | 'p0_days'
  | 'p1_days'
  | 'p2_days'
  | 'p3_days'
  | 'critical_days'
  | 'high_days'
  | 'medium_days'
  | 'low_days'
  | 'info_days'
  | 'warning_threshold_pct'
  | 'escalation_enabled'
>

export const PRIORITY_WINDOWS: {
  key: 'p0_days' | 'p1_days' | 'p2_days' | 'p3_days'
  label: string
}[] = [
  { key: 'p0_days', label: 'P0' },
  { key: 'p1_days', label: 'P1' },
  { key: 'p2_days', label: 'P2' },
  { key: 'p3_days', label: 'P3' },
]

export const SEVERITY_WINDOWS: {
  key: 'critical_days' | 'high_days' | 'medium_days' | 'low_days' | 'info_days'
  label: string
  short: string
  dot: 'critical' | 'high' | 'medium' | 'low' | 'info'
}[] = [
  { key: 'critical_days', label: 'Critical', short: 'C', dot: 'critical' },
  { key: 'high_days', label: 'High', short: 'H', dot: 'high' },
  { key: 'medium_days', label: 'Medium', short: 'M', dot: 'medium' },
  { key: 'low_days', label: 'Low', short: 'L', dot: 'low' },
  { key: 'info_days', label: 'Info', short: 'I', dot: 'info' },
]

/** Platform defaults when no policy governs an asset. */
export const PLATFORM_DEFAULT_WINDOWS: SlaWindowValues = {
  p0_days: DEFAULT_SLA_FORM.p0_days,
  p1_days: DEFAULT_SLA_FORM.p1_days,
  p2_days: DEFAULT_SLA_FORM.p2_days,
  p3_days: DEFAULT_SLA_FORM.p3_days,
  critical_days: DEFAULT_SLA_FORM.critical_days,
  high_days: DEFAULT_SLA_FORM.high_days,
  medium_days: DEFAULT_SLA_FORM.medium_days,
  low_days: DEFAULT_SLA_FORM.low_days,
  info_days: DEFAULT_SLA_FORM.info_days,
  warning_threshold_pct: DEFAULT_SLA_FORM.warning_threshold_pct,
  escalation_enabled: DEFAULT_SLA_FORM.escalation_enabled,
}

/**
 * Compact, two-row rendering of a policy's windows: the priority-class row
 * (which decides the deadline of every classified finding) first, then the
 * severity row (findings without a class).
 */
export function SlaWindows({ policy }: { policy: SlaWindowValues }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-3" aria-label="Priority-class windows">
        {PRIORITY_WINDOWS.map((w) => (
          <div key={w.key} className="flex items-center gap-1 text-sm tabular-nums">
            <span className="text-muted-foreground">{w.label}</span>
            <span className="font-medium">{policy[w.key]}d</span>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3" aria-label="Severity windows">
        {SEVERITY_WINDOWS.map((w) => (
          <div
            key={w.key}
            className="flex items-center gap-1.5 text-xs tabular-nums text-muted-foreground"
            title={w.label}
          >
            <span className={cn('h-2 w-2 rounded-full', SEVERITY_DOT_COLORS[w.dot])} />
            <span>{w.short}</span>
            <span>{policy[w.key]}d</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * The SLA policy that actually governs an asset (its override, else the
 * tenant default, else the platform defaults), read from the API.
 */
export function AssetSlaPolicyCard({ assetId }: { assetId: string }) {
  const { data, isLoading } = useAssetSlaPolicyApi(assetId)
  const policy: SlaWindowValues = data ?? PLATFORM_DEFAULT_WINDOWS
  const source = data ? data.name : 'Platform defaults (no SLA policy is configured)'

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Timer className="h-4 w-4" />
          SLA policy
        </CardTitle>
        <CardDescription>{isLoading ? 'Loading…' : source}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading ? (
          <Skeleton className="h-10 w-full" />
        ) : (
          <>
            <SlaWindows policy={policy} />
            <p className="text-xs text-muted-foreground">
              Findings with a priority class use the P0–P3 windows; others use the severity windows.
              Warning at {policy.warning_threshold_pct}% of the window; deadline notifications{' '}
              {policy.escalation_enabled ? 'on' : 'off'}.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  )
}
