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
  type LucideIcon,
} from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import {
  EmptyState,
  ErrorState,
  FilterSelect,
  RelativeTime,
  SeverityBadge,
} from '@/features/shared'
import { ListToolbar } from '@/features/shared/components/list-toolbar'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
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
import { formatDate } from '@/lib/app-locale'
import { BreakText } from '@/features/shared/components/break-text'

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
          <Link href={exposureHref} className="break-words text-primary hover:underline">
            {change.new}
          </Link>
        ) : (
          <span className="break-words">{change.new}</span>
        ))}
      {added.length > 0 && (
        <span className="break-words">
          {t('attackSurface.changes.added', 'Added: {values}', { values: added.join(', ') })}
        </span>
      )}
      {removed.length > 0 && (
        <span className="break-words">
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
    // On a phone a grid: the time sits on the title row and the asset name
    // and the detail take the whole width under it, so a long host name is
    // never squeezed into a narrow column beside the time. From sm up the
    // plain list row of the app: the content, then the time at its end.
    <li className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1 py-3 sm:flex sm:gap-3">
      <Icon
        aria-hidden
        className={cn(
          'col-start-1 row-start-1 mt-0.5 h-4 w-4 shrink-0',
          kind && RISKY.has(kind) ? 'text-destructive' : 'text-muted-foreground'
        )}
      />
      <div className="contents sm:block sm:min-w-0 sm:flex-1 sm:space-y-1">
        <div className="contents text-sm sm:flex sm:flex-wrap sm:items-center sm:gap-2">
          <span className="col-start-2 row-start-1 text-sm font-medium first-letter:uppercase">
            {label}
          </span>
          <span className="col-start-2 col-end-4 row-start-2 min-w-0 text-sm">
            {isLinkableAssetId(change.asset_id) ? (
              <AssetPeekLink assetId={change.asset_id} className="break-words text-primary">
                {name}
              </AssetPeekLink>
            ) : (
              <span className="break-words text-muted-foreground">
                <BreakText>{name}</BreakText>
              </span>
            )}
          </span>
        </div>
        <div className="col-start-2 col-end-4 row-start-3 min-w-0 empty:hidden">
          <ChangeDetail change={change} />
        </div>
      </div>
      <RelativeTime date={change.at} className="col-start-3 row-start-1 shrink-0 text-xs" />
    </li>
  )
}

export function EASMChanges() {
  const { t } = useTranslation()
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
      ? formatDate(new Date(iso), {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
        })
      : ''

  const kindChips = kinds.map((k) => (
    <RemovableFilterChip
      key={k}
      text={t('attackSurface.changes.chip.kind', 'Kind is {kind}', { kind: kindLabel(k) })}
      onRemove={() => toggle(k)}
      removeLabel={t('attackSurface.changes.chip.remove', 'Remove filter {filter}', {
        filter: kindLabel(k),
      })}
    />
  ))
  const chips = explicit
    ? [
        <RemovableFilterChip
          key="window"
          text={t('attackSurface.changes.window', '{from} to {to}', {
            from: fmt(from),
            to: fmt(to),
          })}
          onRemove={clearWindow}
          removeLabel={t('attackSurface.changes.clearWindow', 'Back to recent changes')}
        />,
        ...kindChips,
      ]
    : kindChips

  return (
    <div className="space-y-4">
      <ListToolbar
        start={
          <>
            {!explicit && (
              <FilterSelect<string>
                label={t('attackSurface.changes.windowLabel', 'Time window')}
                value={String(days)}
                clearable={false}
                options={CHANGE_WINDOWS.map((d) => ({
                  value: String(d),
                  label: t('attackSurface.changes.lastDays', 'Last {count} days', { count: d }),
                }))}
                onChange={(v) => setDays(v || '7')}
              />
            )}
            <FilterSelect<ChangeKind>
              label={t('attackSurface.changes.kindsLabel', 'Change kinds')}
              value=""
              options={CHANGE_KINDS.map((k) => ({
                value: k,
                label: kindLabel(k),
                count: counts[k] ?? 0,
              }))}
              onChange={(v) => v && toggle(v)}
            />
          </>
        }
        below={
          chips.length > 0 ? (
            <FilterChipsRow
              label={t('attackSurface.changes.activeFilters', 'Active filters')}
              chips={chips}
            />
          ) : undefined
        }
      />
      <ListTitleRow
        title={t('attackSurface.changes.viewAll', 'All changes')}
        count={
          <ListCount
            total={total}
            loading={isLoading && items.length === 0}
            label={t('attackSurface.changes.count', '{count} changes', { count: total })}
          />
        }
      />

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
