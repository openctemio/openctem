'use client'

/**
 * Attack surface › Changes: what changed on the external attack surface, by
 * kind (RFC-080). The weekly digest links here with its window
 * (?from=&to=); otherwise the last 7, 14 or 30 days.
 */

import { useMemo } from 'react'
import {
  Award,
  CircleOff,
  Cpu,
  Globe,
  History,
  Link2Off,
  Loader2,
  Network,
  PlugZap,
  ShieldAlert,
  TimerReset,
  Unplug,
  X,
  type LucideIcon,
} from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, RelativeTime, SeverityBadge } from '@/features/shared'
import { isLinkableAssetId } from '@/features/findings/lib/asset-link'
import { AssetPeekLink } from '@/features/assets/components/asset-peek'
import { useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import type { EASMChange } from '@/lib/api/generated'
import { cn } from '@/lib/utils'
import { toSeverity } from './easm-overview'
import { useEASMChanges } from '../hooks/use-easm-changes'
import {
  CHANGE_KINDS,
  CHANGE_WINDOWS,
  isChangeKind,
  parseTime,
  type ChangeKind,
} from '../lib/changes'

const KIND_ICON: Record<ChangeKind, LucideIcon> = {
  dns_dangling: Link2Off,
  exposure_new: ShieldAlert,
  port_opened: PlugZap,
  host_added: Globe,
  cert_expiring: TimerReset,
  cert_changed: Award,
  dns_changed: Network,
  tech_changed: Cpu,
  port_closed: Unplug,
  host_removed: CircleOff,
}

/** Kinds that need attention are tinted. */
const RISKY = new Set<ChangeKind>(['dns_dangling', 'exposure_new', 'port_opened', 'cert_expiring'])

function useKindLabel() {
  const { t } = useTranslation()
  return (k: ChangeKind) => {
    switch (k) {
      case 'dns_dangling':
        return t('attackSurface.kind.dns_dangling', 'Dangling DNS')
      case 'exposure_new':
        return t('attackSurface.kind.exposure_new', 'New exposure')
      case 'port_opened':
        return t('attackSurface.kind.port_opened', 'Port opened')
      case 'host_added':
        return t('attackSurface.kind.host_added', 'New host')
      case 'cert_expiring':
        return t('attackSurface.kind.cert_expiring', 'Certificate expiring')
      case 'cert_changed':
        return t('attackSurface.kind.cert_changed', 'New certificate')
      case 'dns_changed':
        return t('attackSurface.kind.dns_changed', 'DNS changed')
      case 'tech_changed':
        return t('attackSurface.kind.tech_changed', 'Technology changed')
      case 'port_closed':
        return t('attackSurface.kind.port_closed', 'Port closed')
      case 'host_removed':
        return t('attackSurface.kind.host_removed', 'Host gone')
    }
  }
}

function ChangeDetail({ change }: { change: EASMChange }) {
  const { t } = useTranslation()
  const added = change.added ?? []
  const removed = change.removed ?? []
  // The exposures list has no detail route: open it on this exposure's title.
  const exposureHref =
    change.exposure_id && change.new
      ? `/exposures?state=all&q=${encodeURIComponent(change.new)}`
      : undefined
  return (
    <div className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
      {change.severity && <SeverityBadge severity={toSeverity(change.severity)} />}
      {change.exposure_id &&
        change.new &&
        (exposureHref ? (
          <Link href={exposureHref} className="break-all text-primary hover:underline">
            {change.new}
          </Link>
        ) : (
          <span className="break-all">{change.new}</span>
        ))}
      {added.length > 0 && (
        <span className="break-all">
          {t('attackSurface.changes.added', 'Added: {values}', { values: added.join(', ') })}
        </span>
      )}
      {removed.length > 0 && (
        <span className="break-all">
          {t('attackSurface.changes.removed', 'Removed: {values}', { values: removed.join(', ') })}
        </span>
      )}
    </div>
  )
}

function ChangeRow({ change }: { change: EASMChange }) {
  const { t } = useTranslation()
  const kindLabel = useKindLabel()
  // A kind this build does not know yet (the API may add one first) is shown
  // as itself, neutral, never as a new exposure.
  const known = isChangeKind(change.kind ?? '')
  const kind = known ? (change.kind as ChangeKind) : undefined
  const Icon = kind ? KIND_ICON[kind] : History
  const label = kind ? kindLabel(kind) : (change.kind ?? '').replace(/_/g, ' ')
  const name = change.asset_name || t('attackSurface.changes.noAsset', 'Not linked to an asset')
  return (
    <li className="flex items-start gap-3 py-3">
      <Icon
        aria-hidden
        className={cn(
          'mt-0.5 h-4 w-4 shrink-0',
          kind && RISKY.has(kind) ? 'text-destructive' : 'text-muted-foreground'
        )}
      />
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-medium first-letter:uppercase">{label}</span>
          {isLinkableAssetId(change.asset_id) ? (
            <AssetPeekLink assetId={change.asset_id} className="break-all text-primary">
              {name}
            </AssetPeekLink>
          ) : (
            <span className="break-all text-muted-foreground">{name}</span>
          )}
        </div>
        <ChangeDetail change={change} />
      </div>
      <RelativeTime date={change.at} className="shrink-0 text-xs" />
    </li>
  )
}

export function EASMChanges() {
  const { t, locale } = useTranslation()
  const kindLabel = useKindLabel()
  const [kindParam, setKinds] = useUrlFilterList('kind')
  const [daysParam, setDays] = useUrlFilter('days', '7')
  const [fromParam, setFrom] = useUrlFilter('from', '')
  const [toParam, setTo] = useUrlFilter('to', '')
  const from = parseTime(fromParam)
  const to = parseTime(toParam)
  const explicit = !!from && !!to
  const kinds = useMemo(() => kindParam.filter(isChangeKind), [kindParam])
  const days = CHANGE_WINDOWS.find((d) => String(d) === daysParam) ?? 7

  const {
    items,
    counts,
    total,
    error,
    isLoading,
    allowed,
    hasMore,
    loadMore,
    loadingMore,
    mutate,
  } = useEASMChanges({
    from: explicit ? from : undefined,
    to: explicit ? to : undefined,
    days,
    kinds,
  })

  const clearWindow = () => {
    setFrom('')
    setTo('')
  }

  const toggle = (k: ChangeKind) =>
    setKinds((prev) => (prev.includes(k) ? prev.filter((v) => v !== k) : [...prev, k]))

  if (!allowed) {
    return (
      <EmptyState
        icon={History}
        title={t('attackSurface.changes.noAccessTitle', 'Access denied')}
        description={t(
          'attackSurface.changes.noAccess',
          'You do not have permission to view assets. Ask your administrator for access.'
        )}
      />
    )
  }

  const fmt = (iso?: string) =>
    iso
      ? new Date(iso).toLocaleDateString(locale, {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
        })
      : ''

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-end gap-3">
        {explicit ? (
          <div className="flex items-center gap-2 text-sm">
            <span>
              {t('attackSurface.changes.window', '{from} to {to}', {
                from: fmt(from),
                to: fmt(to),
              })}
            </span>
            <Button variant="ghost" size="sm" onClick={clearWindow}>
              <X className="me-1 h-4 w-4" aria-hidden />
              {t('attackSurface.changes.clearWindow', 'Back to recent changes')}
            </Button>
          </div>
        ) : (
          <Select value={String(days)} onValueChange={setDays}>
            <SelectTrigger
              className="w-44"
              aria-label={t('attackSurface.changes.windowLabel', 'Time window')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CHANGE_WINDOWS.map((d) => (
                <SelectItem key={d} value={String(d)}>
                  {t('attackSurface.changes.lastDays', 'Last {count} days', { count: d })}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      <div
        role="group"
        aria-label={t('attackSurface.changes.kindsLabel', 'Change kinds')}
        className="flex flex-wrap gap-2"
      >
        {CHANGE_KINDS.map((k) => {
          const active = kinds.includes(k)
          const Icon = KIND_ICON[k]
          return (
            <Button
              key={k}
              type="button"
              size="sm"
              variant={active ? 'secondary' : 'outline'}
              className={cn(active && 'ring-1 ring-ring')}
              aria-pressed={active}
              onClick={() => toggle(k)}
            >
              <Icon className="me-1 h-3.5 w-3.5" aria-hidden />
              {kindLabel(k)}
              <span className="ms-1 tabular-nums">{counts[k] ?? 0}</span>
            </Button>
          )
        })}
      </div>

      {error ? (
        <ErrorState
          title={t('attackSurface.changes.errorTitle', 'attack surface changes')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : isLoading && items.length === 0 ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={History}
          title={t('attackSurface.changes.emptyTitle', 'Nothing changed')}
          description={
            total > 0
              ? t(
                  'attackSurface.changes.emptyFiltered',
                  'No change of the selected kinds in this window.'
                )
              : t(
                  'attackSurface.changes.empty',
                  'No host, port, certificate, DNS, technology or exposure change in this window.'
                )
          }
        />
      ) : (
        <>
          <ol className="divide-y rounded-md border px-4">
            {items.map((c) => (
              <ChangeRow key={`${c.id}-${c.kind}`} change={c} />
            ))}
          </ol>
          {hasMore && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void loadMore()}
              disabled={loadingMore}
            >
              {loadingMore && <Loader2 className="me-1 h-4 w-4 animate-spin" />}
              {t('attackSurface.changes.loadMore', 'Show older changes')}
            </Button>
          )}
        </>
      )}
    </div>
  )
}
