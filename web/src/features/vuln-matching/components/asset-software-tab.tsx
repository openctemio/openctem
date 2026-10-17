'use client'

import * as React from 'react'
import Link from '@/components/link'
import { ChevronDown, ChevronRight, Package } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { useComponentsList } from '@/features/components'
import { cn } from '@/lib/utils'
import {
  EmptyState,
  ErrorState,
  EPSSScoreBadge,
  RelativeTime,
  SeverityBadge,
} from '@/features/shared'
import { normalizeSeverity, SEVERITY_LEVELS, type SeverityLevel } from '@/lib/severity'

import { useAssetSoftware } from '../api'
import {
  reasonLabel,
  sourceLabel,
  type AssetSoftwareMatchResponse,
  type AssetSoftwareResponse,
} from '../types'

interface AssetSoftwareTabProps {
  assetId: string
  /** The asset's type: a repository or application also links to its components. */
  assetType?: string
  className?: string
}

/** Asset types whose packages come from SBOMs and have a components view. */
const PACKAGE_ASSET_TYPES = new Set(['repository', 'application'])

/**
 * The asset's Software tab (RFC-066): every product and version scans saw
 * on the asset, each with the CVEs its version falls in, scored the way the
 * matcher scores them. Matches below the organization's policy are listed
 * too, marked "Below policy".
 */
export function AssetSoftwareTab({ assetId, assetType, className }: AssetSoftwareTabProps) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAssetSoftware(assetId)
  const packages = PACKAGE_ASSET_TYPES.has(assetType ?? '')

  if (isLoading) {
    return (
      <div className={cn('space-y-2', className)} aria-busy="true">
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
      </div>
    )
  }
  if (error) {
    return (
      <div className={className}>
        <ErrorState
          title={t('assets.software.listName', 'the software list')}
          error={error}
          onRetry={() => void mutate()}
        />
      </div>
    )
  }
  const items = data?.data ?? []
  if (items.length === 0) {
    return (
      <div className={cn('space-y-3', className)}>
        {packages && <ComponentsLink assetId={assetId} />}
        <EmptyState
          icon={Package}
          title={t('assets.software.emptyTitle', 'No software seen yet')}
          description={t(
            'assets.software.emptyHint',
            'Software is what the asset runs, matched against CVEs. It comes from three places:'
          )}
        />
        <ul className="space-y-1.5 text-sm text-muted-foreground">
          <li>
            <Link
              href="/ci-cd"
              className="font-medium text-foreground underline-offset-2 hover:underline"
            >
              {t('assets.software.fromSbom', 'SBOM uploads from CI')}
            </Link>{' '}
            {t(
              'assets.software.fromSbomHint',
              'for repositories and applications (their packages).'
            )}
          </li>
          <li>
            <Link
              href="/scans"
              className="font-medium text-foreground underline-offset-2 hover:underline"
            >
              {t('assets.software.fromScans', 'Service and version detection scans')}
            </Link>{' '}
            {t(
              'assets.software.fromScansHint',
              'for hosts and services (server banners, web servers and frameworks with a version).'
            )}
          </li>
          <li>
            <Link
              href="/sensors"
              className="font-medium text-foreground underline-offset-2 hover:underline"
            >
              {t('assets.software.fromSensor', 'An endpoint sensor')}
            </Link>{' '}
            {t('assets.software.fromSensorHint', 'for software installed on a host.')}
          </li>
        </ul>
      </div>
    )
  }
  return (
    <div className={cn('space-y-3', className)}>
      {packages && <ComponentsLink assetId={assetId} />}
      <ul
        className="divide-y rounded-lg border"
        aria-label={t('assets.sheet.tab.software', 'Software')}
      >
        {items.map((item) => (
          <SoftwareRow
            key={item.id ?? `${item.product}-${item.version}`}
            item={item}
            assetId={assetId}
          />
        ))}
      </ul>
    </div>
  )
}

/** A repository's or application's package count and a link to them. */
function ComponentsLink({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const { data } = useComponentsList({ asset_id: assetId, page: 1, per_page: 1 })
  const total = data?.total
  if (total === undefined) return null
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm">
      <span>
        {t('assets.software.components', '{count} components from SBOMs', { count: total })}
      </span>
      <Link
        href={`/components?asset_id=${encodeURIComponent(assetId)}`}
        className="font-medium underline-offset-2 hover:underline"
      >
        {t('assets.software.viewComponents', 'View components')}
      </Link>
    </div>
  )
}

/** Counts of matches by severity, highest first, for the row summary. */
export function severityCounts(matches: AssetSoftwareMatchResponse[] | undefined) {
  const counts = new Map<SeverityLevel, number>()
  for (const m of matches ?? []) {
    const s = normalizeSeverity(m.severity) ?? 'info'
    counts.set(s, (counts.get(s) ?? 0) + 1)
  }
  return SEVERITY_LEVELS.filter((s) => counts.has(s)).map((s) => ({
    severity: s,
    count: counts.get(s) ?? 0,
  }))
}

function SoftwareRow({ item, assetId }: { item: AssetSoftwareResponse; assetId: string }) {
  const { t } = useTranslation()
  const [open, setOpen] = React.useState(false)
  const matches = item.matches ?? []
  const counts = severityCounts(matches)
  const panelId = `software-${item.id}`
  return (
    <li>
      <button
        type="button"
        className="flex w-full items-start gap-3 px-3 py-2.5 text-left hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={panelId}
        disabled={matches.length === 0}
      >
        <span className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground">
          {matches.length > 0 &&
            (open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />)}
        </span>
        <span className="min-w-0 flex-1 space-y-1">
          <span className="flex flex-wrap items-center gap-1.5">
            <span className="font-medium">{item.product}</span>
            <span className="tabular-nums">
              {item.version || t('assets.software.versionUnknown', 'version unknown')}
            </span>
            {item.qualifier && (
              <Badge
                variant="outline"
                title={t(
                  'assets.software.qualifierHint',
                  'Distribution build: the vendor may have back-ported fixes'
                )}
              >
                {item.qualifier}
              </Badge>
            )}
            {item.known ? (
              <Badge variant="secondary">{t('assets.software.cpeMatched', 'CPE matched')}</Badge>
            ) : (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge variant="outline" tabIndex={0}>
                    {t('assets.software.noCpe', 'No CPE match: CVEs not checked')}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent className="max-w-xs text-xs">
                  {t(
                    'assets.software.noCpeHint',
                    'The name did not match a product the vulnerability feed knows (no CPE), so no CVE is checked against it. A scanner that reports a CPE, or a version of a known product, makes it matchable.'
                  )}
                </TooltipContent>
              </Tooltip>
            )}
            {item.stale && (
              <Badge variant="outline" className="text-warning">
                {t('assets.software.stale', 'Not seen for 30 days')}
              </Badge>
            )}
          </span>
          <span className="block text-xs text-muted-foreground">
            {[
              item.vendor,
              item.location,
              t(`assets.software.source.${item.source ?? ''}`, sourceLabel(item.source ?? '')),
              t('assets.software.confidence', 'confidence {value}', {
                value: item.confidence ?? 0,
              }),
            ]
              .filter(Boolean)
              .join(' · ')}
            {item.last_seen_at && (
              <>
                {` · ${t('assets.software.lastSeen', 'last seen')} `}
                <RelativeTime date={item.last_seen_at} />
              </>
            )}
          </span>
        </span>
        <span
          className="flex shrink-0 flex-wrap justify-end gap-1"
          aria-label={t('assets.software.cvesBySeverity', 'CVEs by severity')}
        >
          {counts.length === 0 ? (
            <span className="text-xs text-muted-foreground">
              {item.known
                ? t('assets.software.noCves', 'No CVEs')
                : t('assets.software.notChecked', 'Not checked')}
            </span>
          ) : (
            counts.map(({ severity, count }) => (
              <span key={severity} className="inline-flex items-center gap-1 text-xs">
                <SeverityBadge severity={severity} />
                <span className="tabular-nums">{count}</span>
              </span>
            ))
          )}
        </span>
      </button>
      {open && matches.length > 0 && (
        <div id={panelId} className="border-t bg-muted/30 px-3 py-2">
          <ul className="space-y-2">
            {matches.map((m) => (
              <MatchRow key={m.cve_id} match={m} assetId={assetId} />
            ))}
          </ul>
        </div>
      )}
    </li>
  )
}

function MatchRow({ match, assetId }: { match: AssetSoftwareMatchResponse; assetId: string }) {
  const { t } = useTranslation()
  const href = `/findings?cve_id=${encodeURIComponent(match.cve_id ?? '')}&asset_id=${encodeURIComponent(assetId)}`
  const severity = normalizeSeverity(match.severity) ?? 'info'
  return (
    <li className="space-y-1 text-sm">
      <div className="flex flex-wrap items-center gap-1.5">
        <Link href={href} className="font-medium underline-offset-2 hover:underline">
          {match.cve_id}
        </Link>
        <SeverityBadge severity={severity} />
        {match.in_kev && <Badge variant="destructive">KEV</Badge>}
        {(match.epss ?? 0) > 0 && <EPSSScoreBadge score={match.epss} size="sm" />}
        <Badge variant={match.label === 'likely' ? 'default' : 'outline'}>
          {match.label === 'likely'
            ? t('assets.software.likely', 'Likely')
            : t('assets.software.potential', 'Potential')}{' '}
          · {match.confidence ?? 0}
        </Badge>
        {match.in_policy ? (
          <Badge variant="secondary">{t('assets.software.finding', 'Finding')}</Badge>
        ) : (
          <Badge variant="outline" className="text-muted-foreground">
            {t('assets.software.belowPolicy', 'Below policy')}
          </Badge>
        )}
      </div>
      <div className="text-xs text-muted-foreground">
        {t('assets.software.range', 'Affected range:')}{' '}
        <span className="tabular-nums">
          {match.range || t('assets.software.rangeNotStated', 'not stated')}
        </span>
      </div>
      {(match.reasons ?? []).length > 0 && (
        <ul className="list-disc pl-5 text-xs text-muted-foreground">
          {(match.reasons ?? []).map((r) => (
            <li key={r}>{t(`assets.software.reason.${r}`, reasonLabel(r))}</li>
          ))}
        </ul>
      )}
    </li>
  )
}
