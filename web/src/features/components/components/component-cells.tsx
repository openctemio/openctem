'use client'

/**
 * Small cells shared by the components list, detail and graph: ecosystem,
 * open findings by severity, KEV, fix, licenses, relationship and scope.
 */

import { KevBadge } from '@/components/ui/kev-badge'
import { CheckCircle2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'
import type { DependencyScope, Relationship, SeverityCounts } from '../api/types'

/** The severities findings are counted under (info is not counted). */
const SEVERITIES = SEVERITY_LEVELS.filter((s): s is keyof SeverityCounts => s !== 'info')

export function useSeverityLabel() {
  const { t } = useTranslation()
  return (s: string) =>
    ({
      critical: t('components.severity.critical', 'Critical'),
      high: t('components.severity.high', 'High'),
      medium: t('components.severity.medium', 'Medium'),
      low: t('components.severity.low', 'Low'),
    })[s] ?? s
}

export function EcosystemBadge({
  ecosystem,
  className,
}: {
  ecosystem: string
  className?: string
}) {
  return (
    <Badge variant="outline" className={cn('font-mono text-[11px] font-normal', className)}>
      {ecosystem}
    </Badge>
  )
}

/** Open findings by severity as compact counts; a dash when there are none. */
export function SeverityCountsCell({
  counts,
  className,
}: {
  counts: SeverityCounts
  className?: string
}) {
  const { t } = useTranslation()
  const label = useSeverityLabel()
  const total = SEVERITIES.reduce((n, s) => n + (counts[s] ?? 0), 0)
  if (total === 0) {
    return (
      <span className={cn('text-xs text-muted-foreground', className)}>
        {t('components.vulns.none', 'None')}
      </span>
    )
  }
  return (
    <span
      className={cn('inline-flex flex-wrap items-center gap-1.5', className)}
      aria-label={SEVERITIES.map((s) => `${counts[s] ?? 0} ${label(s)}`).join(', ')}
    >
      {SEVERITIES.map((s) =>
        counts[s] ? (
          <span
            key={s}
            className="inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs tabular-nums"
            title={label(s)}
          >
            <span aria-hidden className={cn('h-1.5 w-1.5 rounded-full', SEVERITY_DOT_COLORS[s])} />
            {counts[s]}
            <span className="sr-only">{label(s)}</span>
          </span>
        ) : null
      )}
    </span>
  )
}

type Translate = ReturnType<typeof useTranslation>['t']

/**
 * A package's open vulnerabilities as words, most severe first, then the
 * known-exploited count: "1 critical, 2 high, 1 known exploited". Empty when
 * there are none.
 */
export function componentVulnWords(
  item: { vulnerabilities: SeverityCounts; kev: number },
  t: Translate
): string[] {
  const words: string[] = []
  const name: Record<keyof SeverityCounts, string> = {
    critical: t('components.vulns.critical', '{count} critical', {
      count: item.vulnerabilities.critical ?? 0,
    }),
    high: t('components.vulns.high', '{count} high', { count: item.vulnerabilities.high ?? 0 }),
    medium: t('components.vulns.medium', '{count} medium', {
      count: item.vulnerabilities.medium ?? 0,
    }),
    low: t('components.vulns.low', '{count} low', { count: item.vulnerabilities.low ?? 0 }),
  }
  for (const s of SEVERITIES) if (item.vulnerabilities[s]) words.push(name[s])
  if (item.kev) {
    words.push(t('components.vulns.kev', '{count} known exploited', { count: item.kev }))
  }
  return words
}

export function KevPill({ count }: { count: number }) {
  const { t } = useTranslation()
  if (!count) return null
  return (
    <KevBadge
      title={t('components.kev.hint', 'Known exploited vulnerabilities (CISA KEV)')}
      label={
        count > 1
          ? t('components.kev.count', 'KEV {count}', { count })
          : t('components.kev.one', 'KEV')
      }
    />
  )
}

export function FixPill({ available, compact = false }: { available: boolean; compact?: boolean }) {
  const { t } = useTranslation()
  const label = t('components.fix.available', 'Fix available')
  if (!available) return <span className="text-xs text-muted-foreground">—</span>
  return (
    <span className="inline-flex items-center gap-1 text-xs text-success" title={label}>
      <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
      {compact ? <span className="sr-only">{label}</span> : label}
    </span>
  )
}

export function LicenseList({
  licenses,
  max = 1,
  oneLine = false,
}: {
  licenses: string[]
  max?: number
  /** In a table row: never wraps; plain text, a long license id ends in an ellipsis. */
  oneLine?: boolean
}) {
  const { t } = useTranslation()
  if (!licenses.length) {
    return (
      <span className="text-xs text-muted-foreground">
        {t('components.license.unknown', 'Unknown')}
      </span>
    )
  }
  const shown = licenses.slice(0, max)
  const more = licenses.length - shown.length
  return (
    <span
      className={cn(
        'min-w-0 items-center gap-1',
        oneLine ? 'flex max-w-full flex-nowrap' : 'inline-flex flex-wrap'
      )}
      title={licenses.join(', ')}
    >
      {shown.map((l) =>
        // A table row: plain text that ends in an ellipsis (a badge keeps
        // its whole width and would be cut at the cell's edge).
        oneLine ? (
          <span key={l} className="min-w-0 truncate">
            {l}
          </span>
        ) : (
          <Badge key={l} variant="secondary" className="max-w-[12rem] truncate font-normal">
            {l}
          </Badge>
        )
      )}
      {more > 0 && <span className="shrink-0 text-xs text-muted-foreground">+{more}</span>}
    </span>
  )
}

export function useRelationshipLabel() {
  const { t } = useTranslation()
  return (r: Relationship | string) =>
    ({
      direct: t('components.relationship.direct', 'Direct'),
      transitive: t('components.relationship.transitive', 'Transitive'),
      unknown: t('components.relationship.unknown', 'Unknown'),
    })[r] ?? r
}

export function useScopeLabel() {
  const { t } = useTranslation()
  return (s: DependencyScope | string | undefined) =>
    ({
      runtime: t('components.scope.runtime', 'Runtime'),
      development: t('components.scope.development', 'Development'),
      test: t('components.scope.test', 'Test'),
      optional: t('components.scope.optional', 'Optional'),
      build: t('components.scope.build', 'Build'),
      provided: t('components.scope.provided', 'Provided'),
    })[s ?? 'runtime'] ?? s
}

export function RelationshipPill({ relationship }: { relationship: Relationship }) {
  const label = useRelationshipLabel()
  return (
    <Badge
      variant="outline"
      className={cn(
        'font-normal',
        relationship === 'direct' && 'border-primary/40 text-primary',
        relationship === 'unknown' && 'text-muted-foreground'
      )}
    >
      {label(relationship)}
    </Badge>
  )
}
