'use client'

import * as React from 'react'
import Link from '@/components/link'
import { ChevronDown, ChevronRight, Package } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
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
  className?: string
}

/**
 * The asset's Software tab (RFC-066): every product and version scans saw
 * on the asset, each with the CVEs its version falls in, scored the way the
 * matcher scores them. Matches below the organization's policy are listed
 * too, marked "Below policy".
 */
export function AssetSoftwareTab({ assetId, className }: AssetSoftwareTabProps) {
  const { data, error, isLoading, mutate } = useAssetSoftware(assetId)

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
        <ErrorState title="the software list" error={error} onRetry={() => void mutate()} />
      </div>
    )
  }
  const items = data?.data ?? []
  if (items.length === 0) {
    return (
      <EmptyState
        icon={Package}
        title="No software seen yet"
        description="Software appears here when scans identify it: HTTP technology detection, service banners and port scans. CVEs that affect a version come from the vulnerability feed."
        className={className}
      />
    )
  }
  return (
    <ul className={cn('divide-y rounded-lg border', className)} aria-label="Software">
      {items.map((item) => (
        <SoftwareRow
          key={item.id ?? `${item.product}-${item.version}`}
          item={item}
          assetId={assetId}
        />
      ))}
    </ul>
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
            <span className="tabular-nums">{item.version || 'version unknown'}</span>
            {item.qualifier && (
              <Badge
                variant="outline"
                title="Distribution build: the vendor may have back-ported fixes"
              >
                {item.qualifier}
              </Badge>
            )}
            {item.known ? (
              <Badge variant="secondary">Known product</Badge>
            ) : (
              <Badge
                variant="outline"
                title="Not a product the vulnerability feed knows; never matched"
              >
                Unrecognised
              </Badge>
            )}
            {item.stale && (
              <Badge variant="outline" className="text-warning">
                Not seen for 30 days
              </Badge>
            )}
          </span>
          <span className="block text-xs text-muted-foreground">
            {[
              item.vendor,
              item.location,
              sourceLabel(item.source ?? ''),
              `confidence ${item.confidence ?? 0}`,
            ]
              .filter(Boolean)
              .join(' · ')}
            {item.last_seen_at && (
              <>
                {' · last seen '}
                <RelativeTime date={item.last_seen_at} />
              </>
            )}
          </span>
        </span>
        <span className="flex shrink-0 flex-wrap justify-end gap-1" aria-label="CVEs by severity">
          {counts.length === 0 ? (
            <span className="text-xs text-muted-foreground">No CVEs</span>
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
          {match.label === 'likely' ? 'Likely' : 'Potential'} · {match.confidence ?? 0}
        </Badge>
        {match.in_policy ? (
          <Badge variant="secondary">Finding</Badge>
        ) : (
          <Badge variant="outline" className="text-muted-foreground">
            Below policy
          </Badge>
        )}
      </div>
      <div className="text-xs text-muted-foreground">
        Affected range: <span className="tabular-nums">{match.range || 'not stated'}</span>
      </div>
      {(match.reasons ?? []).length > 0 && (
        <ul className="list-disc pl-5 text-xs text-muted-foreground">
          {(match.reasons ?? []).map((r) => (
            <li key={r}>{reasonLabel(r)}</li>
          ))}
        </ul>
      )}
    </li>
  )
}
