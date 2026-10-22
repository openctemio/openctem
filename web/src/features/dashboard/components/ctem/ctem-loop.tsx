'use client'

import Link from '@/components/link'
import type { ReactNode } from 'react'
import { Card } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import {
  coverageState,
  openCountState,
  STATE_STRIPE,
  STATE_TEXT,
  type CtemState,
} from '../../lib/ctem-colors'
import { DRILL } from '../../lib/drill'
import type {
  ExecutiveSummary,
  ScanCoverage,
  ThreatIntelStats,
  ValidationCoverage,
} from '../../hooks/use-ctem-dashboard'

interface Stage {
  index: string
  name: string
  href: string
  value: ReactNode
  sub: string
  flag?: string
  state: CtemState
}

function StageCard({ stage }: { stage: Stage }) {
  return (
    <Link href={stage.href} className="group">
      <Card className="relative flex h-full flex-col gap-1.5 overflow-hidden p-3.5 transition-colors group-hover:border-muted-foreground/40 group-focus-visible:border-muted-foreground/40">
        <span className={cn('absolute inset-y-0 left-0 w-[3px]', STATE_STRIPE[stage.state])} />
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold">{stage.name}</span>
          <span className="text-xs text-muted-foreground">{stage.index}</span>
        </div>
        <div className="text-2xl font-semibold leading-none tabular-nums">{stage.value}</div>
        <p className="text-xs text-muted-foreground">{stage.sub}</p>
        {stage.flag && (
          <span className={cn('mt-0.5 text-xs font-medium', STATE_TEXT[stage.state])}>
            {stage.flag}
          </span>
        )}
      </Card>
    </Link>
  )
}

interface CtemLoopProps {
  summary?: ExecutiveSummary
  scanCoverage?: ScanCoverage
  validationCoverage?: ValidationCoverage
  threatIntel?: ThreatIntelStats
  /**
   * Scoping readiness from GET /scoping/summary (ready of total checklist
   * rows) and how many crown jewels are designated. Absent on an API without
   * the summary: the tile then shows crown jewels at risk, without claiming
   * none are designated.
   */
  scoping?: { ready: number; total: number; crownJewels: number }
  isLoading?: boolean
  /**
   * Reads that failed. A stage fed by a failed read shows "—" and says so,
   * never a confident 0.
   */
  errors?: { summary?: unknown; scan?: unknown; validation?: unknown; threat?: unknown }
}

function Unit({ children }: { children: ReactNode }) {
  return <small className="text-xs font-normal text-muted-foreground">{children}</small>
}

export function CtemLoop({
  summary,
  scanCoverage,
  validationCoverage,
  threatIntel,
  scoping,
  isLoading,
  errors,
}: CtemLoopProps) {
  const { t } = useTranslation()
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-5">
        {[0, 1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-[104px] w-full" />
        ))}
      </div>
    )
  }

  const atRisk = summary?.crown_jewels_at_risk ?? 0
  const scanPct = scanCoverage?.coverage_percent ?? 0
  const p0 = summary?.p0_open ?? 0
  const valPct = validationCoverage?.overall_pct ?? 0
  // Null: no open finding has an SLA, so the share is not measured.
  const slaPct = summary?.sla_compliance_pct ?? null
  // The tenant's own exposure to the KEV catalog, never the catalog's size.
  const kevOpen = threatIntel?.kev?.tenant_open_count ?? 0

  const stages: Stage[] = [
    // Scoping opens the Scoping overview and shows its readiness. It used to
    // show crown jewels AT RISK and say "designate" when that was 0, even
    // with nine designated.
    scoping
      ? {
          index: '01',
          name: t('dashboardMetrics.loop.stage.scoping'),
          href: '/scoping',
          value: (
            <>
              {scoping.ready}
              <Unit>{t('dashboardMetrics.loop.readyOf', undefined, { total: scoping.total })}</Unit>
            </>
          ),
          sub:
            scoping.crownJewels === 1
              ? t('dashboardMetrics.loop.crownSubOne', undefined, { open: atRisk })
              : t('dashboardMetrics.loop.crownSubMany', undefined, {
                  n: scoping.crownJewels,
                  open: atRisk,
                }),
          flag:
            scoping.crownJewels === 0 ? t('dashboardMetrics.loop.designateCrownJewels') : undefined,
          state: scoping.ready >= scoping.total ? 'good' : 'warn',
        }
      : {
          index: '01',
          name: t('dashboardMetrics.loop.stage.scoping'),
          href: '/scoping',
          value: (
            <>
              {atRisk} <Unit>{t('dashboardMetrics.loop.crownUnit')}</Unit>
            </>
          ),
          sub: t('dashboardMetrics.loop.crownFallback'),
          state: atRisk > 0 ? 'crit' : 'good',
        },
    {
      index: '02',
      name: t('dashboardMetrics.loop.stage.discovery'),
      href: '/scans',
      value: (
        <>
          {scanPct.toFixed(0)}
          <Unit>%</Unit>
        </>
      ),
      sub: t('dashboardMetrics.loop.scanSub', undefined, { n: scanCoverage?.never_scanned ?? 0 }),
      flag:
        (scanCoverage?.critical_uncovered ?? 0) > 0
          ? t('dashboardMetrics.loop.criticalUncovered', undefined, {
              n: scanCoverage?.critical_uncovered ?? 0,
            })
          : undefined,
      state: coverageState(scanPct),
    },
    {
      index: '03',
      name: t('dashboardMetrics.loop.stage.prioritize'),
      // The tile counts open P0 findings: open exactly that list.
      href: DRILL.p0Open,
      value: (
        <>
          {p0} <Unit>P0</Unit>
        </>
      ),
      sub: t('dashboardMetrics.loop.openKev', undefined, {
        n: threatIntel ? kevOpen.toLocaleString() : '—',
      }),
      flag: p0 > 0 ? t('dashboardMetrics.hero.exploitableNow') : undefined,
      state: openCountState(p0),
    },
    {
      index: '04',
      name: t('dashboardMetrics.loop.stage.validate'),
      // Validation coverage, the same API the Validation overview headlines
      // (it used to open Compensating controls, another feature).
      href: DRILL.validation,
      value: (
        <>
          {valPct.toFixed(0)}
          <Unit>%</Unit>
        </>
      ),
      sub: t('dashboardMetrics.loop.validatedOf', undefined, {
        n: validationCoverage?.validated ?? 0,
        total: validationCoverage?.total ?? 0,
      }),
      flag: valPct === 0 ? t('dashboardMetrics.loop.noneRunYet') : undefined,
      state: coverageState(valPct),
    },
    {
      index: '05',
      name: t('dashboardMetrics.loop.stage.mobilize'),
      // The tile counts open findings past their SLA (overdue or exceeded).
      href: DRILL.slaBreached,
      value: (
        <>
          {slaPct === null ? (
            '—'
          ) : (
            <>
              {slaPct.toFixed(0)}
              <Unit>%</Unit>
            </>
          )}
        </>
      ),
      sub:
        slaPct === null
          ? t('dashboardMetrics.loop.slaNotMeasured', 'No open finding has an SLA')
          : t('dashboardMetrics.loop.sla', undefined, { n: summary?.sla_breached ?? 0 }),
      flag: slaPct !== null && slaPct >= 90 ? t('dashboardMetrics.loop.onTrack') : undefined,
      // Not measured (no open finding has an SLA) is neutral, never green.
      state: slaPct === null ? 'none' : slaPct >= 90 ? 'good' : slaPct >= 70 ? 'warn' : 'crit',
    },
  ]

  // A stage whose source failed, or whose figure has no denominator, shows
  // "—" with the reason instead of 0 %, in neutral grey: an unmeasured stage is
  // neither good nor a warning.
  const failed = t('dashboardMetrics.state.loadFailed', "Couldn't load these figures")
  const blank = (stage: Stage, sub: string): Stage => ({
    ...stage,
    value: '—',
    sub,
    flag: undefined,
    state: 'none',
  })
  const shown = stages.map((s) => {
    switch (s.index) {
      case '01':
        return !scoping && errors?.summary && !summary ? blank(s, failed) : s
      case '02':
        if (errors?.scan && !scanCoverage) return blank(s, failed)
        if (scanCoverage?.total_scannable === 0)
          return blank(
            s,
            t('dashboardMetrics.loop.noScannable', 'No scannable assets in your scope')
          )
        return s
      case '03':
        return errors?.summary && !summary ? blank(s, failed) : s
      case '04':
        if (errors?.validation && !validationCoverage) return blank(s, failed)
        if (validationCoverage && validationCoverage.total === 0)
          return blank(
            s,
            t('dashboardMetrics.loop.nothingToValidate', 'No open findings to validate')
          )
        return s
      case '05':
        return errors?.summary && !summary ? blank(s, failed) : s
      default:
        return s
    }
  })

  return (
    <div>
      <h2 className="mb-2 text-sm font-semibold tracking-tight">
        {t('dashboardMetrics.loop.title')}
      </h2>
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-5">
        {shown.map((s) => (
          <StageCard key={s.index} stage={s} />
        ))}
      </div>
    </div>
  )
}
