'use client'

/**
 * The attack surface "Decide" panel (research/117 option B): the scope
 * decisions that still need a person, one card each, from
 * GET /api/v1/easm/suggestions. Nothing here adds anything on its own:
 * accepting a card is an ordinary bulk add of exact scope entries
 * (POST /scope/targets/bulk; scope write permission, step-up handled by the
 * shared client, approvals, audit). Addresses are never added because a name
 * points at them: a person decides. The addresses card is grouped by network
 * (easm-address-groups.tsx, research/425): one decision per group, a
 * selection or all waiting addresses, each after a dialog listing what
 * changes; shared and CDN addresses are listed apart and only added one at a
 * time; "Is this network yours?" is asked once per network. "Not now" hides a
 * card on the overview for 30 days or until it shows something new. Only a
 * card that offers something is a decision; the badge counts address groups
 * that wait.
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { useState } from 'react'
import Link from '@/components/link'
import { Crosshair, Globe } from 'lucide-react'
import { toast } from 'sonner'

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
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { EmptyState, ErrorState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { EASMSuggestionCard } from '@/lib/api/generated'
import { createScopeTargetsBulk, invalidateScopeCache } from '@/features/scope/api/use-scope-api'
import { reportBulkResult } from '@/features/scope/components/add-to-scope-action'
import { refreshEASMSuggestions, useEASMSuggestions } from '../hooks/use-easm-suggestions'
import { EASMRuleSuggestions } from './easm-rule-suggestions'
import { AddressGroupsCard } from './easm-address-groups'

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

export function EASMDecidePanel({ compact = false }: { compact?: boolean }) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const { cards, error, isLoading, mutate } = useEASMSuggestions()
  useSettleSignal(isLoading && !cards)
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

  // A card that offers nothing (only shared or already checked addresses)
  // is not a decision: the overview leaves it out, the Review tab shows it as
  // a quiet line. "Not now" hides a card from the overview for 30 days (or
  // until it shows something new), for this viewer.
  const all = cards?.cards ?? []
  const shown = compact ? all.filter((c) => (c.count ?? 0) > 0 && !snoozed(tenantId, c)) : all
  // The name-rule cards only the Review tab lists: when they are all that
  // waits, the overview says so in one line.
  const ruleCount = cards?.name_rules ?? 0
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
            {t('attackSurface.decide.viewAll', 'Open Review')}
          </Link>
        </div>
      )}
      {!compact && (cards?.total ?? 0) === 0 && (
        <EmptyState
          icon={Crosshair}
          title={t('attackSurface.decide.emptyTitle', 'Nothing to decide')}
          description={t(
            'attackSurface.decide.emptyDescription',
            'Every address your names resolve to and every asset you confirmed is in scope, or nothing has been found yet.'
          )}
        />
      )}
      {shown.map((c) =>
        c.kind === 'addresses_behind_names' ? (
          (c.count ?? 0) > 0 || (c.groups ?? []).length > 0 ? (
            <AddressGroupsCard
              key={c.kind}
              card={c}
              canAdd={!!cards?.can_add}
              onSnooze={compact ? () => snooze(c) : undefined}
              limit={compact ? 3 : undefined}
            />
          ) : null
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
    </section>
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
