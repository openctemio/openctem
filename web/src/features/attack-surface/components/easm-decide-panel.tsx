'use client'

/**
 * The attack surface "Decide" panel (research/117 option B): the scope
 * decisions that still need a person, one card each, from
 * GET /api/v1/easm/suggestions. Nothing here adds anything on its own:
 * accepting a card is an ordinary bulk add of exact scope entries
 * (POST /scope/targets/bulk; scope write permission, step-up handled by the
 * shared client, approvals, audit). Addresses are never added because a name
 * points at them: a person decides, shared and CDN addresses are listed apart
 * with no button, and an address whose network is unknown says so. Each
 * address shows what was seen on it (open ports, other names); the
 * organization's own prefix is offered as one rule; "Not ours" records a
 * rejection (never suggested or scanned again); "Not now" hides the card on
 * the overview for 30 days or until it shows something new. While
 * unclassified assets get low-impact checks (RFC-054 §16), only addresses
 * whose network is unknown wait for a decision.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { AlertTriangle, ChevronDown, ChevronUp, Crosshair, Globe, Network } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { EmptyState, ErrorState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { UNDO_TOAST_MS } from '@/lib/undo-toast'
import type { EASMSuggestionAddress, EASMSuggestionCard } from '@/lib/api/generated'
import {
  createScopeTargetsBulk,
  invalidateScopeCache,
  useScopeSettingsApi,
} from '@/features/scope/api/use-scope-api'
import { decideAttribution } from '@/features/assets/api/triage-api'
import { Permission, useHasPermission } from '@/lib/permissions'
import { reportBulkResult } from '@/features/scope/components/add-to-scope-action'
import { refreshEASMSuggestions, useEASMSuggestions } from '../hooks/use-easm-suggestions'
import { EASMRuleSuggestions } from './easm-rule-suggestions'

type TFn = ReturnType<typeof useTranslation>['t']

/** The Suggestions tab. */
export const EASM_SUGGESTIONS_HREF = '/attack-surface/review'

/** How long "Not now" hides a card for this viewer (unless what it shows changes). */
const SNOOZE_MS = 30 * 24 * 60 * 60 * 1000
const SHOWN = 8

interface ScopeItem {
  target_type: string
  pattern: string
}

/** A count-dependent message: `<key>.one` for 1, `<key>.other` otherwise. */
function plural(t: TFn, key: string, count: number, one: string, other: string, vars = {}) {
  return count === 1
    ? t(`${key}.one`, one, { count, ...vars })
    : t(`${key}.other`, other, { count, ...vars })
}

function snoozeKey(tenantId: string | undefined, kind: string) {
  return `easm-decide-snooze:${tenantId ?? ''}:${kind}`
}

/**
 * What a card shows, as one string: a snoozed card comes back early when it
 * changes (a new address, a new open port, a new name behind one).
 */
export function cardFingerprint(c: EASMSuggestionCard): string {
  const addrs = (c.addresses ?? []).map(
    (a) =>
      `${a.address}|${(a.ports ?? []).join(',')}|${(a.resolved_from ?? []).join(',')}|${(a.other_names ?? []).join(',')}`
  )
  const assets = (c.assets ?? []).map((a) => a.name ?? '')
  const prefixes = (c.prefix_rules ?? []).map((p) => p.prefix ?? '')
  return [...addrs, ...assets, ...prefixes].sort().join(';')
}

function snoozed(tenantId: string | undefined, c: EASMSuggestionCard): boolean {
  try {
    const raw = window.localStorage.getItem(snoozeKey(tenantId, c.kind ?? ''))
    if (!raw) return false
    const s = JSON.parse(raw) as { until?: number; fp?: string }
    return (s.until ?? 0) > Date.now() && s.fp === cardFingerprint(c)
  } catch {
    return false
  }
}

/** Hides a card from the overview for 30 days, or until it shows something new. */
function snoozeCard(tenantId: string | undefined, c: EASMSuggestionCard) {
  try {
    window.localStorage.setItem(
      snoozeKey(tenantId, c.kind ?? ''),
      JSON.stringify({ until: Date.now() + SNOOZE_MS, fp: cardFingerprint(c) })
    )
  } catch {
    // Storage unavailable: the card stays.
  }
}

/** One line about an address's network; unknown is said, never implied safe. */
export function addressNetworkText(t: TFn, a: EASMSuggestionAddress): string {
  const n = a.network
  if (a.shared) {
    const provider = n?.provider || n?.org || ''
    return t(`attackSurface.decide.shared.${a.shared}`, a.shared, { provider })
  }
  if (!n?.known) return t('attackSurface.decide.networkUnknown', 'Network unknown')
  return [n.asn, n.org].filter(Boolean).join(' ')
}

/**
 * The organization's unclassified-scans mode in force (RFC-054 §16): with
 * low_impact or full, an address whose network is known and not shared
 * already gets checks without an entry, so only unknown networks wait for a
 * decision. Anything else (off, Strict, an older API) keeps every address
 * waiting.
 */
function useUnclassifiedScanning(): boolean {
  const { data } = useScopeSettingsApi()
  const mode = (data as { unclassified_scans_effective?: string } | undefined)
    ?.unclassified_scans_effective
  return mode === 'low_impact' || mode === 'full'
}

export function EASMDecidePanel({ compact = false }: { compact?: boolean }) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const { cards, error, isLoading, mutate } = useEASMSuggestions()
  const [, setTick] = useState(0)

  const snooze = (c: EASMSuggestionCard) => {
    snoozeCard(tenantId, c)
    setTick((n) => n + 1)
  }

  if (error) {
    return (
      <ErrorState
        title={t('attackSurface.decide.errorTitle', 'the suggestions')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading && !cards) {
    // The compact panel renders nothing when no card is waiting: no skeleton,
    // so the overview does not jump when the answer is empty.
    return compact ? null : <Skeleton className="h-28 w-full rounded-xl" />
  }

  // "Not now" hides a card from the overview for 30 days (or until it shows
  // something new), for this viewer; the Suggestions tab lists every card.
  const shown = (cards?.cards ?? []).filter((c) => !compact || !snoozed(tenantId, c))
  // The tab badge also counts the name-rule cards, which only the Suggestions
  // tab lists: when they are all that waits, say so in one line.
  const ruleCount = Math.max(0, (cards?.total ?? 0) - (cards?.cards?.length ?? 0))
  if (compact && shown.length === 0) {
    if (ruleCount === 0) return null
    return (
      <p
        className="flex items-center justify-between gap-2 text-sm"
        data-testid="decide-rules-line"
      >
        <span>
          {plural(
            t,
            'attackSurface.decide.rulesWaiting',
            ruleCount,
            '1 name rule waiting',
            '{count} name rules waiting'
          )}
        </span>
        <Link href={EASM_SUGGESTIONS_HREF} className="text-primary hover:underline">
          {t('attackSurface.decide.review', 'Review')}
        </Link>
      </p>
    )
  }

  return (
    <section aria-label={t('attackSurface.decide.label', 'Decide')} className="space-y-3">
      {compact && (
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-base font-semibold">
            {t('attackSurface.decide.title', 'Waiting for your decision')}
          </h2>
          <Link href={EASM_SUGGESTIONS_HREF} className="text-sm text-primary hover:underline">
            {t('attackSurface.decide.viewAll', 'All suggestions')}
          </Link>
        </div>
      )}
      {shown.map((c) =>
        c.kind === 'addresses_behind_names' ? (
          <AddressesCard
            key={c.kind}
            card={c}
            canAdd={!!cards?.can_add}
            onSnooze={compact ? () => snooze(c) : undefined}
          />
        ) : c.kind === 'confirmed_out_of_scope' ? (
          <ConfirmedCard
            key={c.kind}
            card={c}
            canAdd={!!cards?.can_add}
            onSnooze={compact ? () => snooze(c) : undefined}
          />
        ) : null
      )}
      {!compact && (
        <EASMRuleSuggestions namesOnly onApplied={() => void refreshEASMSuggestions()} />
      )}
      {!compact && shown.length === 0 && (cards?.total ?? 0) === 0 && (
        <EmptyState
          icon={Crosshair}
          title={t('attackSurface.decide.emptyTitle', 'Nothing to decide')}
          description={t(
            'attackSurface.decide.emptyDescription',
            'Every address your names resolve to and every asset you confirmed is in scope, or nothing has been found yet.'
          )}
        />
      )}
    </section>
  )
}

function AddressesCard({
  card,
  canAdd,
  onSnooze,
}: {
  card: EASMSuggestionCard
  canAdd: boolean
  onSnooze?: () => void
}) {
  const { t } = useTranslation()
  const canDecide = useHasPermission(Permission.AssetsWrite)
  const scanning = useUnclassifiedScanning()
  const [open, setOpen] = useState(false)
  const [confirming, setConfirming] = useState<ScopeItem[] | null>(null)
  const [rejecting, setRejecting] = useState(false)
  const offered = card.addresses ?? []
  const shared = card.shared_addresses ?? []
  // Waiting for a decision: every offered address, or only the unknown
  // networks while unclassified assets already get checks.
  const waiting = scanning ? offered.filter((a) => !a.network?.known) : offered
  const checked = scanning ? offered.filter((a) => a.network?.known) : []
  const count = waiting.length
  const sharedCount = card.shared_count ?? 0
  const prefixes = card.prefix_rules ?? []
  const toItems = (as: EASMSuggestionAddress[]): ScopeItem[] =>
    as.map((a) => ({ target_type: 'ip_address', pattern: a.address ?? '' }))
  const reasonNames = Array.from(new Set(offered.flatMap((a) => a.resolved_from ?? []))).slice(0, 5)

  const notOurs = async () => {
    const ids = waiting.map((a) => a.asset_id ?? '').filter(Boolean)
    try {
      await decideAttribution(ids, 'rejected')
      await refreshEASMSuggestions()
      toast.success(
        plural(
          t,
          'attackSurface.decide.notOursDone',
          ids.length,
          '1 address marked not yours',
          '{count} addresses marked not yours'
        ),
        {
          duration: UNDO_TOAST_MS,
          action: {
            label: t('attackSurface.decide.undo', 'Undo'),
            onClick: () =>
              void decideAttribution(ids, 'automatic')
                .then(() => refreshEASMSuggestions())
                .catch((err) =>
                  toast.error(
                    getErrorMessage(err, t('attackSurface.decide.undoFailed', 'Undo failed'))
                  )
                ),
          },
        }
      )
      setRejecting(false)
    } catch (err) {
      toast.error(getErrorMessage(err, t('attackSurface.decide.notOursFailed', 'Not saved')))
    }
  }

  return (
    <Card data-testid="decide-card-addresses">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Network className="h-4 w-4 text-muted-foreground" aria-hidden />
          {count > 0
            ? plural(
                t,
                'attackSurface.decide.addresses.title',
                count,
                '1 address your in-scope names resolve to',
                '{count} addresses your in-scope names resolve to'
              )
            : t(
                'attackSurface.decide.addresses.titleShared',
                'Addresses your in-scope names resolve to'
              )}
        </CardTitle>
        <CardDescription>
          {t(
            'attackSurface.decide.addresses.value',
            'Add them to scan every port of these addresses. Today only the names are scanned, so a service that answers on the address without a name is missed.'
          )}{' '}
          {t(
            'attackSurface.decide.addresses.caution',
            'A name never makes an address yours: it may be shared, or released and now used by someone else. Add only addresses you know are yours.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-2 text-xs">
          {waiting.some((a) => !a.network?.known) && (
            <Badge
              variant="outline"
              className="h-auto gap-1 whitespace-normal border-warning/40 text-start text-warning"
            >
              <AlertTriangle className="h-3 w-3" aria-hidden />
              {plural(
                t,
                'attackSurface.decide.addresses.unknown',
                waiting.filter((a) => !a.network?.known).length,
                'Network unknown for 1: check it is yours',
                'Network unknown for {count}: check they are yours'
              )}
            </Badge>
          )}
          {sharedCount > 0 && (
            <Badge variant="outline" className="h-auto whitespace-normal text-start">
              {plural(
                t,
                'attackSurface.decide.addresses.shared',
                sharedCount,
                '1 shared or CDN address not offered',
                '{count} shared or CDN addresses not offered'
              )}
            </Badge>
          )}
          {card.truncated && (
            <Badge variant="outline" className="h-auto whitespace-normal text-start">
              {t('attackSurface.decide.truncated', 'More after these: the card comes back')}
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {canAdd && count > 0 && (
            <Button size="sm" onClick={() => setConfirming(toItems(waiting))}>
              {plural(
                t,
                'attackSurface.decide.add',
                count,
                'Add 1 to scope',
                'Add {count} to scope'
              )}
            </Button>
          )}
          {canDecide && count > 0 && (
            <Button size="sm" variant="outline" onClick={() => setRejecting(true)}>
              {t('attackSurface.decide.notOurs', 'Not ours')}
            </Button>
          )}
          {onSnooze && (
            <Button size="sm" variant="outline" onClick={onSnooze}>
              {t('attackSurface.decide.notNow', 'Not now')}
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
            {open ? (
              <ChevronUp className="h-4 w-4" aria-hidden />
            ) : (
              <ChevronDown className="h-4 w-4" aria-hidden />
            )}
            {open
              ? t('attackSurface.decide.hideList', 'Hide list')
              : t('attackSurface.decide.viewList', 'View list')}
          </Button>
        </div>
        {!canAdd && count > 0 && (
          <p className="text-xs text-muted-foreground">
            {t(
              'attackSurface.decide.needsScopeWrite',
              'Adding to scope needs permission to edit scope.'
            )}
          </p>
        )}
        {prefixes.length > 0 && (
          <div className="space-y-1" data-testid="decide-prefix-rules">
            <p className="text-sm font-medium">
              {t('attackSurface.decide.prefixHeading', 'Your own network')}
            </p>
            <ul className="divide-y rounded-md border text-sm">
              {prefixes.map((p) => (
                <li
                  key={p.prefix}
                  className="flex flex-col gap-1 px-3 py-2 sm:flex-row sm:items-center sm:gap-3"
                >
                  <code className="shrink-0 font-mono text-xs">{p.prefix}</code>
                  <span className="min-w-0 flex-1 text-xs text-muted-foreground">
                    {plural(
                      t,
                      'attackSurface.decide.prefixHolds',
                      p.addresses ?? 0,
                      'Announced by your seeded network; holds 1 of these addresses',
                      'Announced by your seeded network; holds {count} of these addresses'
                    )}
                  </span>
                  {canAdd && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        setConfirming([{ target_type: 'cidr', pattern: p.prefix ?? '' }])
                      }
                    >
                      {t('attackSurface.decide.addPrefix', 'Add {prefix}', {
                        prefix: p.prefix ?? '',
                      })}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        {open && (
          <div className="space-y-3">
            {waiting.length > 0 && <AddressList addresses={waiting} />}
            {checked.length > 0 && (
              <div className="space-y-1">
                <p className="text-sm font-medium">
                  {t(
                    'attackSurface.decide.checkedHeading',
                    'Already get low-impact checks (add to scope for a full scan)'
                  )}
                </p>
                <AddressList addresses={checked} />
              </div>
            )}
            {shared.length > 0 && (
              <div className="space-y-1">
                <p className="text-sm font-medium">
                  {t('attackSurface.decide.sharedHeading', 'Shared, not offered')}
                </p>
                <AddressList addresses={shared} />
              </div>
            )}
          </div>
        )}
      </CardContent>
      <AcceptDialog
        open={confirming !== null}
        onOpenChange={(o) => !o && setConfirming(null)}
        items={confirming ?? []}
        reason={t(
          'attackSurface.decide.addresses.reason',
          'Addresses behind in-scope names: {names}',
          { names: reasonNames.join(', ') }
        )}
      />
      <ConfirmDialog
        open={rejecting}
        onOpenChange={setRejecting}
        title={plural(
          t,
          'attackSurface.decide.notOursTitle',
          count,
          'Mark 1 address as not yours?',
          'Mark {count} addresses as not yours?'
        )}
        desc={t(
          'attackSurface.decide.notOursDesc',
          'They are never scanned or suggested again, until someone undoes it on the asset.'
        )}
        confirmText={t('attackSurface.decide.notOurs', 'Not ours')}
        handleConfirm={() => void notOurs()}
      />
    </Card>
  )
}

function AddressList({ addresses }: { addresses: EASMSuggestionAddress[] }) {
  const { t } = useTranslation()
  return (
    <ul className="divide-y rounded-md border text-sm" data-testid="decide-address-list">
      {addresses.map((a) => (
        <li key={a.asset_id ?? a.address} className="space-y-0.5 px-3 py-2">
          <div className="flex flex-col gap-0.5 sm:flex-row sm:items-baseline sm:gap-3">
            <code className="shrink-0 font-mono text-xs sm:w-36">{a.address}</code>
            <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">
              {t('attackSurface.decide.from', 'From {names}', {
                names: (a.resolved_from ?? []).join(', '),
              })}
            </span>
            <span
              className={
                a.network?.known || a.shared
                  ? 'text-xs text-muted-foreground'
                  : 'text-xs text-warning'
              }
            >
              {addressNetworkText(t, a)}
            </span>
          </div>
          {((a.ports ?? []).length > 0 || (a.other_names ?? []).length > 0) && (
            <p className="text-xs text-muted-foreground">
              {(a.ports ?? []).length > 0 &&
                t('attackSurface.decide.seenPorts', 'Open ports seen: {ports}', {
                  ports: (a.ports ?? []).join(', '),
                })}
              {(a.ports ?? []).length > 0 && (a.other_names ?? []).length > 0 && ' · '}
              {(a.other_names ?? []).length > 0 &&
                t('attackSurface.decide.otherNames', 'Also named {names} (not in scope)', {
                  names: (a.other_names ?? []).join(', '),
                })}
            </p>
          )}
        </li>
      ))}
    </ul>
  )
}

function ConfirmedCard({
  card,
  canAdd,
  onSnooze,
}: {
  card: EASMSuggestionCard
  canAdd: boolean
  onSnooze?: () => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const assets = card.assets ?? []
  const count = card.count ?? 0
  const items: ScopeItem[] = assets.map((a) => ({
    target_type: a.target_type ?? 'domain',
    pattern: a.name ?? '',
  }))
  return (
    <Card data-testid="decide-card-confirmed">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Globe className="h-4 w-4 text-muted-foreground" aria-hidden />
          {plural(
            t,
            'attackSurface.decide.confirmed.title',
            count,
            '1 asset you confirmed is not in scope',
            '{count} assets you confirmed are not in scope'
          )}
        </CardTitle>
        <CardDescription>
          {t(
            'attackSurface.decide.confirmed.description',
            'They were confirmed as yours before confirming added a scope entry, so scans skip them. Add their exact entries to scan them.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          {canAdd && (
            <Button size="sm" onClick={() => setConfirming(true)}>
              {plural(
                t,
                'attackSurface.decide.add',
                count,
                'Add 1 to scope',
                'Add {count} to scope'
              )}
            </Button>
          )}
          {onSnooze && (
            <Button size="sm" variant="outline" onClick={onSnooze}>
              {t('attackSurface.decide.notNow', 'Not now')}
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
            {open
              ? t('attackSurface.decide.hideList', 'Hide list')
              : t('attackSurface.decide.viewList', 'View list')}
          </Button>
        </div>
        {open && (
          <ul className="divide-y rounded-md border text-sm">
            {assets.map((a) => (
              <li key={a.asset_id} className="px-3 py-2">
                <code className="break-all font-mono text-xs">{a.name}</code>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
      <AcceptDialog
        open={confirming}
        onOpenChange={setConfirming}
        items={items}
        reason={t(
          'attackSurface.decide.confirmed.reason',
          'Assets confirmed as the organization’s'
        )}
      />
    </Card>
  )
}

/** Confirms a card: the exact entries it adds, then one bulk add. */
function AcceptDialog({
  open,
  onOpenChange,
  items,
  reason,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  items: ScopeItem[]
  reason: string
}) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      const res = await createScopeTargetsBulk({ items, reason: reason.slice(0, 1000) })
      reportBulkResult(t, res)
      await invalidateScopeCache()
      await refreshEASMSuggestions()
      onOpenChange(false)
    } catch (err) {
      toast.error(getErrorMessage(err, t('scope.bulk.failed', 'Could not add to scope')))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {plural(
              t,
              'attackSurface.decide.add',
              items.length,
              'Add 1 to scope',
              'Add {count} to scope'
            )}
          </DialogTitle>
          <DialogDescription>
            {t(
              'attackSurface.decide.acceptDescription',
              'Each one becomes an exact scope entry, so scans may reach it. Exclusions still win, and you can remove an entry on the Scope page at any time.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <ul className="space-y-1 font-mono text-xs">
            {items.slice(0, SHOWN).map((i) => (
              <li key={`${i.target_type}:${i.pattern}`} className="truncate">
                {i.pattern}
              </li>
            ))}
            {items.length > SHOWN && (
              <li className="font-sans text-muted-foreground">
                {t('scope.bulk.more', 'and {count} more', { count: items.length - SHOWN })}
              </li>
            )}
          </ul>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={() => void submit()} disabled={busy || items.length === 0}>
            {busy ? t('scope.bulk.adding', 'Adding…') : t('scope.bulk.confirm', 'Add to scope')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
