'use client'

import * as React from 'react'
import Link from '@/components/link'
import {
  AlertCircle,
  AlertTriangle,
  Bug,
  ChevronRight,
  ExternalLink,
  FileWarning,
  Info,
  KeyRound,
  Settings2,
  Shield,
} from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSheetFooter, EmptyState, ErrorState } from '@/features/shared'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import { SEVERITY_BADGE_SOFT, SEVERITY_TEXT_COLORS } from '@/lib/severity-colors'
import { SEVERITY_LEVELS, normalizeSeverity } from '@/lib/severity'

import type { Asset, AssetFinding } from '../types/asset.types'
import { assetFindingsHref } from './service-cells/open-findings-link'
import type { FindingStatus } from '@/features/findings/types'
import { useFindingsApi } from '@/features/findings/api/use-findings-api'
import type { ApiFinding } from '@/features/findings/api/finding-api.types'

interface AssetFindingsProps {
  assetId: string
  assetName?: string
  /** The asset's own open-findings figure (the tab badge): the footer count and the severity chips come from it, not from the loaded page. */
  findingCount?: number
  severityCounts?: Asset['findingSeverityCounts']
  className?: string
}

/** A finding row as this tab shows it: the real status, not a folded one. */
type TabFinding = Omit<AssetFinding, 'status'> & { status: FindingStatus }

// Colours come from the shared severity source (dark-mode aware).
const SEVERITY_ICONS: Record<AssetFinding['severity'], React.ElementType> = {
  critical: AlertCircle,
  high: AlertTriangle,
  medium: AlertTriangle,
  low: Info,
  info: Info,
}

const typeConfig: Record<AssetFinding['type'], { label: string; icon: React.ElementType }> = {
  vulnerability: { label: 'Vulnerability', icon: Bug },
  misconfiguration: { label: 'Misconfiguration', icon: Settings2 },
  exposure: { label: 'Exposure', icon: ExternalLink },
  secret: { label: 'Secret', icon: KeyRound },
  compliance: { label: 'Compliance', icon: Shield },
}

/**
 * Map API finding to the AssetFinding shape used by this component.
 */
function mapApiFinding(f: ApiFinding): TabFinding {
  // Map API finding_type/source to the component's FindingType
  const typeMap: Record<string, AssetFinding['type']> = {
    vulnerability: 'vulnerability',
    misconfiguration: 'misconfiguration',
    secret: 'secret',
    compliance: 'compliance',
  }
  const findingType: AssetFinding['type'] =
    (f.finding_type && typeMap[f.finding_type]) || 'vulnerability'

  const status = f.status as FindingStatus

  // none (CVSS 0.0) is shown as info; an unknown value too, never dropped.
  const severity: AssetFinding['severity'] = normalizeSeverity(f.severity) ?? 'info'

  return {
    id: f.id,
    type: findingType,
    severity,
    status,
    title: f.title || f.message,
    description: f.description || f.message,
    assetId: f.asset_id,
    assetName: f.asset?.name || '',
    assetType: (f.asset?.type as AssetFinding['assetType']) || 'host',
    cveId: f.cve_id,
    cvssScore: f.cvss_score,
    cweId: f.cwe_ids?.[0],
    rule: f.rule_id || f.rule_name,
    remediation: f.remediation?.recommendation || f.recommendation,
    references: f.remediation?.references,
    firstSeen: f.first_detected_at || f.created_at,
    lastSeen: f.last_seen_at || f.updated_at,
    resolvedAt: f.resolved_at,
  }
}

export function AssetFindings({
  assetId,
  findingCount,
  severityCounts: assetSeverityCounts,
  className,
}: AssetFindingsProps) {
  const { t } = useTranslation()
  // Open findings only: the tab badge, the chips, this list and the footer
  // link (which opens the default open lens) then name the same set.
  const {
    data: response,
    isLoading,
    error,
    mutate,
  } = useFindingsApi({ asset_id: assetId, state: 'open', page: 1, per_page: 50 })

  const findings = React.useMemo<TabFinding[]>(() => {
    if (!response?.data) return []
    return response.data.map(mapApiFinding)
  }, [response])

  // The asset's own per-severity counts; the loaded page (50 rows) only
  // stands in when the row carries none.
  const severityCounts = React.useMemo(() => {
    const counts = Object.fromEntries(SEVERITY_LEVELS.map((s) => [s, 0])) as Record<
      AssetFinding['severity'],
      number
    >
    if (assetSeverityCounts && Object.keys(assetSeverityCounts).length > 0) {
      for (const s of SEVERITY_LEVELS) counts[s] = assetSeverityCounts[s] ?? 0
    } else {
      for (const f of findings) counts[f.severity] += 1
    }
    return counts
  }, [findings, assetSeverityCounts])

  if (isLoading) {
    return (
      <div className={cn('space-y-4', className)}>
        <div className="flex flex-wrap gap-2">
          <Skeleton className="h-8 w-24 rounded-full" />
          <Skeleton className="h-8 w-20 rounded-full" />
          <Skeleton className="h-8 w-22 rounded-full" />
        </div>
        <Separator />
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="py-3">
              <div className="flex items-start gap-3">
                <Skeleton className="h-8 w-8 rounded-lg" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-full" />
                  <Skeleton className="h-3 w-1/2" />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className={className}>
        <ErrorState
          title={t('assetDetail.findingsErrorTitle', 'findings')}
          error={error}
          onRetry={() => mutate()}
        />
      </div>
    )
  }

  if (findings.length === 0) {
    return (
      <EmptyState
        card={false}
        icon={Shield}
        title={t('assetDetail.findingsEmpty', 'No open findings')}
        description={t(
          'assetDetail.findingsEmptyHint',
          'This asset has no open security findings.'
        )}
        className={className}
      />
    )
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* Severity summary */}
      <div className="flex flex-wrap gap-2">
        {SEVERITY_LEVELS.filter((level) => severityCounts[level] > 0).map((level) => {
          const Icon = SEVERITY_ICONS[level]
          return (
            <Badge
              key={level}
              variant="outline"
              className={cn('gap-1.5 font-medium tabular-nums', SEVERITY_BADGE_SOFT[level])}
            >
              <Icon className="h-3.5 w-3.5" />
              {severityCounts[level]} {t(`severity.${level}`, level)}
            </Badge>
          )
        })}
      </div>

      {/* Findings list — flat rows separated by dividers (no card per row).
          The sheet's tab body is the scroll container. */}
      <ul className="divide-y border-y">
        {findings.map((finding) => {
          const type = typeConfig[finding.type]
          const SeverityIcon = SEVERITY_ICONS[finding.severity]
          const TypeIcon = type.icon

          return (
            <li key={finding.id}>
              <Link
                href={`/findings/${finding.id}`}
                className="focus-visible:ring-ring flex items-start gap-3 py-3 transition-colors hover:bg-accent/50 focus-visible:ring-2 focus-visible:outline-none"
              >
                <SeverityIcon
                  className={cn('mt-0.5 h-4 w-4 shrink-0', SEVERITY_TEXT_COLORS[finding.severity])}
                  aria-label={t(`severity.${finding.severity}`, finding.severity)}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h4 className="text-sm font-medium break-words">{finding.title}</h4>
                    <FindingStatusBadge status={finding.status} />
                  </div>
                  {finding.description && finding.description !== finding.title && (
                    <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">
                      {finding.description}
                    </p>
                  )}

                  {/* Metadata */}
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <TypeIcon className="h-3 w-3" />
                      {t(`assets.findings.type.${finding.type}`, type.label)}
                    </span>
                    {finding.cveId && <span className="font-mono">{finding.cveId}</span>}
                    {finding.cvssScore && <span>CVSS {finding.cvssScore}</span>}
                    {finding.rule && <span className="font-mono break-all">{finding.rule}</span>}
                    <span>
                      {t('assets.findings.firstSeen', 'First seen {date}', {
                        date: new Date(finding.firstSeen).toLocaleDateString(),
                      })}
                    </span>
                  </div>

                  {/* Remediation preview */}
                  {finding.remediation && (
                    <p className="mt-2 line-clamp-2 rounded bg-muted/50 p-2 text-xs">
                      <span className="font-medium">
                        {t('assets.findings.remediation', 'Remediation:')}{' '}
                      </span>
                      <span className="text-muted-foreground">{finding.remediation}</span>
                    </p>
                  )}
                </div>
                <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
              </Link>
            </li>
          )
        })}
      </ul>

      {/* View All Link */}
      <DetailSheetFooter>
        <Button asChild variant="outline" className="w-full">
          {/* The same open set as the count, so the list it opens shows that number. */}
          <Link href={assetFindingsHref(assetId)}>
            <FileWarning className="me-2 h-4 w-4" />
            {t('assets.findings.viewOpen', 'View {count} open findings', {
              count: findingCount ?? response?.total ?? findings.length,
            })}
            <ChevronRight className="ms-2 h-4 w-4" />
          </Link>
        </Button>
      </DetailSheetFooter>
    </div>
  )
}
