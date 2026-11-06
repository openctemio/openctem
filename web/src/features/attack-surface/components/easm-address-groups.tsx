'use client'

/**
 * The addresses card of the Decisions lens, grouped (research/425 §5.4-5.5):
 * the addresses the organization's in-scope names resolve to, one group per
 * network (its own prefix, a known network, else a /24 or /48 block) and the
 * shared ones by provider. One decision covers a group, a selection or every
 * waiting address, always after a dialog that lists exactly what changes.
 * "Is this network yours?" records the answer once for the whole network.
 *
 * The server checks every address and range against the caller's own card
 * (POST /easm/suggestions/addresses/*, /networks/*): this component never
 * decides what may be added. A shared or provider address is never part of a
 * bulk add; it can only be added on its own ("Add anyway"). Every decision
 * offers an Undo.
 */

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronUp, Network } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { UNDO_TOAST_MS } from '@/lib/undo-toast'
import type {
  EASMAddressAddResult,
  EASMSuggestionAddress,
  EASMSuggestionCard,
  EASMSuggestionGroup,
} from '@/lib/api/generated'
import { invalidateScopeCache } from '@/features/scope/api/use-scope-api'
import { decideAttribution } from '@/features/assets/api/triage-api'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  addCardAddresses,
  answerNetwork,
  MAX_DECISION_ITEMS,
  rejectCardAddresses,
  removeNetworkSeed,
  removeScopeEntries,
  undoDeclinedNetwork,
} from '../api/address-decisions-api'
import { refreshEASMSuggestions } from '../hooks/use-easm-suggestions'

type TFn = ReturnType<typeof useTranslation>['t']

const K = 'attackSurface.decide.groups'

/** Kinds whose addresses wait or may be added in bulk. */
const OWN_KINDS = new Set(['own_prefix', 'own_network', 'network', 'block'])

function plural(t: TFn, key: string, count: number, one: string, other: string, vars = {}) {
  return count === 1
    ? t(`${key}.one`, one, { count, ...vars })
    : t(`${key}.other`, other, { count, ...vars })
}

/** The network a group stands for, as people read it. */
export function groupNetworkName(g: EASMSuggestionGroup): string {
  return [g.asn, g.org].filter(Boolean).join(' ')
}

/** The group's heading. */
export function groupTitle(t: TFn, g: EASMSuggestionGroup): string {
  const network = groupNetworkName(g)
  switch (g.kind) {
    case 'own_prefix':
      return t(`${K}.title.own_prefix`, 'Your prefix {prefix}', { prefix: g.prefix ?? '' })
    case 'own_network':
      return t(`${K}.title.own_network`, 'Your network {network}', { network })
    case 'network':
      return network
    case 'block':
      return t(`${K}.title.block`, '{prefix}, network not known yet', { prefix: g.prefix ?? '' })
    case 'other_network':
      return t(`${K}.title.other_network`, '{network}, announced by another organization', {
        network,
      })
    case 'declined':
      return t(`${K}.title.declined`, '{network}, you said it is not yours', { network })
    case 'shared_hosting':
      return t(`${K}.title.shared_hosting`, 'Shared hosting')
    default:
      return g.provider || t(`${K}.title.provider`, 'Shared provider network')
  }
}

/** One evidence chip: the signal and how many of the group's addresses carry it. */
export function evidenceText(t: TFn, id: string, count: number, total: number): string {
  const label = t(`${K}.evidence.${id}`, id)
  return count === total
    ? label
    : t(`${K}.evidenceCount`, '{label}: {count} of {total}', {
        label,
        count,
        total,
      })
}

interface Pending {
  kind: 'add' | 'reject' | 'yes' | 'no'
  title: string
  desc: string
  confirm: string
  /** What changes, one line each. */
  items: string[]
  run: () => Promise<void>
}

export function AddressGroupsCard({
  card,
  canAdd,
  onSnooze,
  limit,
}: {
  card: EASMSuggestionCard
  canAdd: boolean
  onSnooze?: () => void
  /** The overview shows the first groups only. */
  limit?: number
}) {
  const { t } = useTranslation()
  const canDecide = useHasPermission(Permission.AssetsWrite)
  const canRemove = useHasPermission(Permission.ScopeDelete)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [pending, setPending] = useState<Pending | null>(null)

  const groups = useMemo(() => card.groups ?? [], [card.groups])
  const waiting = card.count ?? 0
  const own = useMemo(
    () =>
      groups
        .filter((g) => OWN_KINDS.has(g.kind ?? ''))
        .sort((a, b) => Number((b.waiting ?? 0) > 0) - Number((a.waiting ?? 0) > 0)),
    [groups]
  )
  const asked = groups.filter((g) => g.kind === 'other_network')
  const shared = groups.filter((g) => !OWN_KINDS.has(g.kind ?? '') && g.kind !== 'other_network')
  const waitingAddrs = (card.addresses ?? []).map((a) => a.address ?? '').filter(Boolean)
  const byAddress = useMemo(() => {
    const m = new Map<string, EASMSuggestionAddress>()
    for (const list of [card.addresses, card.checked_addresses, card.shared_addresses]) {
      for (const a of list ?? []) if (a.address) m.set(a.address, a)
    }
    return m
  }, [card])

  const toggle = (addrs: string[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev)
      for (const a of addrs) {
        if (on) next.add(a)
        else next.delete(a)
      }
      return next
    })

  const done = async () => {
    setSelected(new Set())
    await refreshEASMSuggestions()
  }

  const reportAdd = (res: EASMAddressAddResult) => {
    const created = res.created ?? 0
    const ids = (res.items ?? []).filter((i) => i.result === 'created' && i.id).map((i) => i.id!)
    const parts: string[] = []
    if (created > 0)
      parts.push(plural(t, `${K}.added`, created, '1 added to scope', '{count} added to scope'))
    if ((res.pending ?? 0) > 0)
      parts.push(
        plural(
          t,
          `${K}.pendingApproval`,
          res.pending ?? 0,
          '1 waits for approval',
          '{count} wait for approval'
        )
      )
    if ((res.existing ?? 0) > 0)
      parts.push(t('scope.bulk.existing', '{count} already in scope', { count: res.existing ?? 0 }))
    if ((res.refused ?? 0) > 0)
      parts.push(t('scope.bulk.refused', '{count} refused', { count: res.refused ?? 0 }))
    const text = parts.join(', ')
    const undo =
      canRemove && ids.length > 0
        ? {
            label: t('attackSurface.decide.undo', 'Undo'),
            onClick: () =>
              void removeScopeEntries(ids)
                .then(async () => {
                  await invalidateScopeCache()
                  await refreshEASMSuggestions()
                })
                .catch((err) =>
                  toast.error(
                    getErrorMessage(err, t('attackSurface.decide.undoFailed', 'Undo failed'))
                  )
                ),
          }
        : undefined
    if ((res.refused ?? 0) > 0 && created === 0) toast.error(text)
    else toast.success(text, { duration: UNDO_TOAST_MS, action: undo })
  }

  const confirmAdd = (addresses: string[], ranges: string[], title: string, shared = false) => {
    const lines = [...ranges, ...addresses.filter((a) => !ranges.some((r) => inRange(a, r)))]
    setPending({
      kind: 'add',
      title,
      desc: shared
        ? t(
            `${K}.addSharedDesc`,
            'This address is shared: other organizations use it too, and scanning it reaches them. Add it only if it is dedicated to you.'
          )
        : t(
            `${K}.addDesc`,
            'Each line becomes a scope entry, so full scans may reach it on the next coverage pass. A name pointing at an address does not prove the address is yours. If your organization requires approval, the entries wait for your approvers. You can remove them on the Scope page.'
          ),
      confirm: t('scope.bulk.confirm', 'Add to scope'),
      items: lines,
      run: async () => {
        const res = await addCardAddresses(addresses, ranges, shared)
        reportAdd(res)
        await invalidateScopeCache()
        await done()
      },
    })
  }

  const confirmReject = (addresses: string[]) => {
    setPending({
      kind: 'reject',
      title: plural(
        t,
        'attackSurface.decide.notOursTitle',
        addresses.length,
        'Mark 1 address as not yours?',
        'Mark {count} addresses as not yours?'
      ),
      desc: t(
        'attackSurface.decide.notOursDesc',
        'They are never scanned or suggested again, until someone undoes it on the asset.'
      ),
      confirm: t('attackSurface.decide.notOurs', 'Not ours'),
      items: addresses,
      run: async () => {
        const res = await rejectCardAddresses(addresses)
        const ids = res.asset_ids ?? []
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
        await done()
      },
    })
  }

  const confirmNetwork = (g: EASMSuggestionGroup, ours: boolean) => {
    const network = groupNetworkName(g)
    const count = g.addresses?.length ?? 0
    setPending({
      kind: ours ? 'yes' : 'no',
      title: ours
        ? t(`${K}.yesTitle`, 'Record {network} as your network?', { network })
        : t(`${K}.noTitle`, 'Mark {network} as not yours?', { network }),
      desc: ours
        ? t(
            `${K}.yesDesc`,
            'Addresses in this network that your in-scope names resolve to, now and later, are added to scope automatically when the evidence is strong, through your approval rules. The others stay here with their evidence. You can remove it under Scope > Networks.'
          )
        : plural(
            t,
            `${K}.noDesc`,
            count,
            'Its address is marked not yours, and you are not asked about this network again.',
            'Its {count} addresses are marked not yours, and you are not asked about this network again.'
          ),
      confirm: ours ? t(`${K}.yes`, 'Yes, it is ours') : t(`${K}.no`, 'No, not ours'),
      items: g.addresses ?? [],
      run: async () => {
        const res = await answerNetwork(g.key ?? '', ours)
        if (ours) {
          const n = res.auto_added ?? 0
          toast.success(
            n > 0
              ? plural(
                  t,
                  `${K}.yesDoneAdded`,
                  n,
                  'Network recorded; 1 entry added',
                  'Network recorded; {count} entries added'
                )
              : t(`${K}.yesDone`, 'Network recorded as yours'),
            {
              duration: UNDO_TOAST_MS,
              action:
                canRemove && res.seed_id
                  ? {
                      label: t('attackSurface.decide.undo', 'Undo'),
                      onClick: () =>
                        void removeNetworkSeed(res.seed_id!)
                          .then(() => refreshEASMSuggestions())
                          .catch((err) =>
                            toast.error(
                              getErrorMessage(
                                err,
                                t('attackSurface.decide.undoFailed', 'Undo failed')
                              )
                            )
                          ),
                    }
                  : undefined,
            }
          )
          await invalidateScopeCache()
        } else {
          const ids = res.rejected?.asset_ids ?? []
          toast.success(t(`${K}.noDone`, 'Network marked not yours'), {
            duration: UNDO_TOAST_MS,
            action: {
              label: t('attackSurface.decide.undo', 'Undo'),
              onClick: () =>
                void Promise.all([
                  res.declined_id ? undoDeclinedNetwork(res.declined_id) : Promise.resolve(),
                  ids.length ? decideAttribution(ids, 'automatic') : Promise.resolve(),
                ])
                  .then(() => refreshEASMSuggestions())
                  .catch((err) =>
                    toast.error(
                      getErrorMessage(err, t('attackSurface.decide.undoFailed', 'Undo failed'))
                    )
                  ),
            },
          })
        }
        await done()
      },
    })
  }

  const undoDecline = async (id: string) => {
    try {
      await undoDeclinedNetwork(id)
      await refreshEASMSuggestions()
    } catch (err) {
      toast.error(getErrorMessage(err, t('attackSurface.decide.undoFailed', 'Undo failed')))
    }
  }

  const sel = Array.from(selected).slice(0, MAX_DECISION_ITEMS)
  const shownOwn = limit ? own.slice(0, limit) : own

  const askedSection = !limit && asked.length > 0 && (
    <section className="space-y-1" aria-labelledby="decide-asked-heading">
      <h3 id="decide-asked-heading" className="text-sm font-medium">
        {t(`${K}.askedHeading`, 'Is this network yours?')}
      </h3>
      <p className="text-xs text-muted-foreground">
        {t(
          `${K}.askedHint`,
          'Another organization announces these networks, so their addresses are not offered. If one is yours (your provider registers it under its name, or your organization uses another name), say so once.'
        )}
      </p>
      <ul className="divide-y rounded-md border" data-testid="decide-asked-groups">
        {asked.map((g) => (
          <GroupRow
            key={g.key}
            group={g}
            byAddress={byAddress}
            selected={selected}
            onToggle={toggle}
            canAdd={canAdd}
            canDecide={canDecide}
            onAdd={(addrs) =>
              confirmAdd(
                addrs,
                [],
                t(`${K}.addAnywayTitle`, 'Add {address} anyway?', { address: addrs[0] }),
                true
              )
            }
            onReject={confirmReject}
            onNetwork={confirmNetwork}
          />
        ))}
      </ul>
    </section>
  )
  const sharedSection = !limit && (shared.length > 0 || (card.checked_count ?? 0) > 0) && (
    <section
      className="space-y-1"
      aria-labelledby="decide-shared-heading"
      data-testid="decide-no-decision"
    >
      <h3 id="decide-shared-heading" className="text-sm font-medium text-muted-foreground">
        {t(`${K}.sharedHeading`, 'No decision needed')}
      </h3>
      {(card.checked_count ?? 0) > 0 && (
        <p className="text-xs text-muted-foreground">
          {plural(
            t,
            'attackSurface.decide.noDecision.checked',
            card.checked_count ?? 0,
            '1 address already gets low-impact checks.',
            '{count} addresses already get low-impact checks.'
          )}
        </p>
      )}
      {shared.length > 0 && (
        <ul className="divide-y rounded-md border" data-testid="decide-shared-groups">
          {shared.map((g) => (
            <GroupRow
              key={g.key}
              group={g}
              byAddress={byAddress}
              selected={selected}
              onToggle={toggle}
              canAdd={canAdd}
              canDecide={canDecide}
              onAdd={(addrs) =>
                confirmAdd(
                  addrs,
                  [],
                  t(`${K}.addAnywayTitle`, 'Add {address} anyway?', { address: addrs[0] }),
                  true
                )
              }
              onReject={confirmReject}
              onNetwork={confirmNetwork}
              onUndoDecline={canDecide ? undoDecline : undefined}
            />
          ))}
        </ul>
      )}
    </section>
  )
  const dialog = (
    <ConfirmDialog
      open={pending !== null}
      onOpenChange={(o) => !o && setPending(null)}
      title={pending?.title ?? ''}
      desc={
        <div className="space-y-2">
          <p>{pending?.desc}</p>
          <ul
            className="max-h-56 space-y-0.5 overflow-auto rounded-md border px-3 py-2 font-mono text-xs"
            data-testid="decide-confirm-items"
          >
            {(pending?.items ?? []).map((i) => (
              <li key={i} className="break-all">
                {i}
              </li>
            ))}
          </ul>
        </div>
      }
      confirmText={pending?.confirm}
      destructive={pending?.kind === 'reject' || pending?.kind === 'no'}
      handleConfirm={async () => {
        const p = pending
        if (!p) return
        try {
          await p.run()
          setPending(null)
        } catch (err) {
          toast.error(getErrorMessage(err, t('attackSurface.decide.notOursFailed', 'Not saved')))
        }
      }}
    />
  )

  // Nothing waits: only the networks to ask about and the shared addresses,
  // quietly, without a card.
  if (waiting === 0) {
    if (limit || (!askedSection && !sharedSection)) return null
    return (
      <div className="space-y-3">
        {askedSection}
        {sharedSection}
        {dialog}
      </div>
    )
  }

  return (
    <Card data-testid="decide-card-addresses">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Network className="h-4 w-4 text-muted-foreground" aria-hidden />
          {plural(
            t,
            'attackSurface.decide.addresses.title',
            waiting,
            '1 address your in-scope names resolve to',
            '{count} addresses your in-scope names resolve to'
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
        <div className="flex flex-wrap items-center gap-2" data-testid="decide-groups-toolbar">
          {sel.length > 0 ? (
            <>
              <span className="text-sm font-medium" aria-live="polite">
                {plural(t, `${K}.selected`, sel.length, '1 selected', '{count} selected')}
              </span>
              {canAdd && (
                <Button
                  size="sm"
                  onClick={() =>
                    confirmAdd(
                      sel,
                      [],
                      plural(t, `${K}.addN`, sel.length, 'Add 1 address', 'Add {count} addresses')
                    )
                  }
                >
                  {t(`${K}.addSelected`, 'Add selected')}
                </Button>
              )}
              {canDecide && (
                <Button size="sm" variant="outline" onClick={() => confirmReject(sel)}>
                  {t('attackSurface.decide.notOurs', 'Not ours')}
                </Button>
              )}
              <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
                {t(`${K}.clear`, 'Clear selection')}
              </Button>
            </>
          ) : (
            <>
              {canAdd && waitingAddrs.length > 0 && (
                <Button
                  size="sm"
                  variant="outline"
                  data-testid="decide-add-all"
                  onClick={() =>
                    confirmAdd(
                      waitingAddrs,
                      [],
                      plural(
                        t,
                        `${K}.addAllTitle`,
                        waitingAddrs.length,
                        'Add the 1 waiting address?',
                        'Add all {count} waiting addresses?'
                      )
                    )
                  }
                >
                  {plural(
                    t,
                    `${K}.addAll`,
                    waitingAddrs.length,
                    'Add all (1)',
                    'Add all ({count})'
                  )}
                </Button>
              )}
              {onSnooze && (
                <Button size="sm" variant="outline" onClick={onSnooze}>
                  {t('attackSurface.decide.notNow', 'Not now')}
                </Button>
              )}
            </>
          )}
        </div>
        {!canAdd && waiting > 0 && (
          <p className="text-xs text-muted-foreground">
            {t(
              'attackSurface.decide.needsScopeWrite',
              'Adding to scope needs permission to edit scope.'
            )}
          </p>
        )}
        {card.truncated && (
          <p className="text-xs text-muted-foreground">
            {t('attackSurface.decide.truncated', 'More after these: the card comes back')}
          </p>
        )}

        {shownOwn.length > 0 && (
          <ul className="divide-y rounded-md border" data-testid="decide-groups">
            {shownOwn.map((g) => (
              <GroupRow
                key={g.key}
                group={g}
                byAddress={byAddress}
                selected={selected}
                onToggle={toggle}
                canAdd={canAdd}
                canDecide={canDecide}
                onAdd={(addrs, ranges) =>
                  confirmAdd(
                    addrs,
                    ranges,
                    ranges.length > 0
                      ? t(`${K}.addRangeTitle`, 'Add {range} to scope?', { range: ranges[0] })
                      : plural(
                          t,
                          `${K}.addN`,
                          addrs.length,
                          'Add 1 address',
                          'Add {count} addresses'
                        )
                  )
                }
                onReject={confirmReject}
                onNetwork={confirmNetwork}
              />
            ))}
          </ul>
        )}
        {limit && own.length > limit && (
          <p className="text-xs text-muted-foreground">
            {plural(
              t,
              `${K}.moreGroups`,
              own.length - limit,
              '1 more group on the Decisions page',
              '{count} more groups on the Decisions page'
            )}
          </p>
        )}

        {askedSection}
        {sharedSection}
      </CardContent>
      {dialog}
    </Card>
  )
}

/** Whether an IPv4 or IPv6 address lies inside a prefix (display only). */
export function inRange(addr: string, prefix: string): boolean {
  const [net, bitsRaw] = prefix.split('/')
  const bits = Number(bitsRaw)
  const a = toBits(addr)
  const n = toBits(net ?? '')
  if (!a || !n || a.length !== n.length || !Number.isFinite(bits)) return false
  return a.slice(0, bits) === n.slice(0, bits)
}

function toBits(ip: string): string | null {
  if (ip.includes('.') && !ip.includes(':')) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some((p) => !(p >= 0 && p <= 255))) return null
    return parts.map((p) => p.toString(2).padStart(8, '0')).join('')
  }
  if (!ip.includes(':')) return null
  const [head, tail] = ip.split('::')
  const h = head ? head.split(':') : []
  const tl = tail !== undefined && tail !== '' ? tail.split(':') : []
  const fill = tail !== undefined ? 8 - h.length - tl.length : 0
  const groups = [...h, ...Array(Math.max(fill, 0)).fill('0'), ...tl]
  if (groups.length !== 8) return null
  return groups
    .map((g) =>
      parseInt(g || '0', 16)
        .toString(2)
        .padStart(16, '0')
    )
    .join('')
}

function GroupRow({
  group: g,
  byAddress,
  selected,
  onToggle,
  canAdd,
  canDecide,
  onAdd,
  onReject,
  onNetwork,
  onUndoDecline,
}: {
  group: EASMSuggestionGroup
  byAddress: Map<string, EASMSuggestionAddress>
  selected: Set<string>
  onToggle: (addrs: string[], on: boolean) => void
  canAdd: boolean
  canDecide: boolean
  onAdd: (addresses: string[], ranges: string[]) => void
  onReject: (addresses: string[]) => void
  onNetwork: (g: EASMSuggestionGroup, ours: boolean) => void
  onUndoDecline?: (id: string) => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const addrs = g.addresses ?? []
  const count = addrs.length
  const selectable = !g.shared
  const inSel = addrs.filter((a) => selected.has(a)).length
  const names = g.resolved_from ?? []
  const shownNames = names.slice(0, 3)
  const title = groupTitle(t, g)
  return (
    <li className="space-y-2 px-3 py-3" data-testid="decide-group" data-kind={g.kind}>
      <div className="flex items-start gap-3">
        {selectable && (
          <Checkbox
            className="mt-0.5"
            checked={inSel === 0 ? false : inSel === count ? true : 'indeterminate'}
            onCheckedChange={(v) => onToggle(addrs, v === true)}
            aria-label={t(`${K}.selectGroup`, 'Select the addresses of {group}', { group: title })}
          />
        )}
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="break-all text-sm font-medium">{title}</span>
            <span className="text-xs text-muted-foreground">
              {plural(t, `${K}.count`, count, '1 address', '{count} addresses')}
            </span>
            {(g.checked ?? 0) > 0 && (g.waiting ?? 0) === 0 && (
              <span className="text-xs text-muted-foreground">
                {t(`${K}.alreadyChecked`, 'already get low-impact checks')}
              </span>
            )}
          </div>
          {names.length > 0 && (
            <p className="break-words text-xs text-muted-foreground">
              {names.length > shownNames.length
                ? t(`${K}.fromMore`, 'From {names} and {count} more', {
                    names: shownNames.join(', '),
                    count: names.length - shownNames.length,
                  })
                : t('attackSurface.decide.from', 'From {names}', { names: shownNames.join(', ') })}
            </p>
          )}
          {((g.evidence ?? []).length > 0 || g.kind === 'block') && (
            <div className="flex flex-wrap gap-1" data-testid="decide-group-evidence">
              {g.kind === 'block' && (
                <Badge
                  variant="outline"
                  className="h-auto whitespace-normal text-start text-warning"
                >
                  {t(`${K}.evidence.network_unknown`, 'No network data yet')}
                </Badge>
              )}
              {(g.evidence ?? []).map((e) => (
                <Badge
                  key={e.id}
                  variant="outline"
                  className={
                    e.kind === 'blocker'
                      ? 'h-auto whitespace-normal text-start text-warning'
                      : 'h-auto whitespace-normal text-start'
                  }
                >
                  {evidenceText(t, e.id ?? '', e.count ?? 0, count)}
                </Badge>
              ))}
            </div>
          )}
          {g.ask_network && (
            <div
              className="flex flex-wrap items-center gap-2 pt-1"
              data-testid="decide-network-question"
            >
              <span className="text-sm">
                {t(`${K}.question`, 'Is {network} your network?', { network: groupNetworkName(g) })}
              </span>
              {canAdd && (
                <Button size="sm" variant="outline" onClick={() => onNetwork(g, true)}>
                  {t(`${K}.yes`, 'Yes, it is ours')}
                </Button>
              )}
              {canDecide && (
                <Button size="sm" variant="outline" onClick={() => onNetwork(g, false)}>
                  {t(`${K}.no`, 'No, not ours')}
                </Button>
              )}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            {canAdd && !g.shared && g.range && (
              <Button size="sm" onClick={() => onAdd(addrs, [g.range!])}>
                {t(`${K}.addRange`, 'Add range {range}', { range: g.range })}
              </Button>
            )}
            {canAdd && !g.shared && !g.range && (
              <Button
                size="sm"
                variant={g.kind === 'block' ? 'outline' : 'default'}
                onClick={() => onAdd(addrs, [])}
              >
                {plural(t, `${K}.addN`, count, 'Add 1 address', 'Add {count} addresses')}
              </Button>
            )}
            {canDecide && g.kind !== 'declined' && (
              <Button size="sm" variant="outline" onClick={() => onReject(addrs)}>
                {t('attackSurface.decide.notOurs', 'Not ours')}
              </Button>
            )}
            {g.kind === 'declined' && g.declined_id && onUndoDecline && (
              <Button size="sm" variant="outline" onClick={() => onUndoDecline(g.declined_id!)}>
                {t(`${K}.askAgain`, 'Ask me again')}
              </Button>
            )}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setOpen((o) => !o)}
              aria-expanded={open}
            >
              {open ? (
                <ChevronUp className="h-4 w-4" aria-hidden />
              ) : (
                <ChevronDown className="h-4 w-4" aria-hidden />
              )}
              {open
                ? t('attackSurface.decide.hideList', 'Hide list')
                : plural(t, `${K}.show`, count, 'Show the address', 'Show {count} addresses')}
            </Button>
          </div>
        </div>
      </div>
      {open && (
        <ul className="ms-7 divide-y rounded-md border text-sm" data-testid="decide-address-list">
          {addrs.map((a) => {
            const item = byAddress.get(a)
            return (
              <li
                key={a}
                className="flex flex-col gap-1 px-3 py-2 sm:flex-row sm:items-center sm:gap-3"
              >
                <div className="flex min-w-0 flex-1 items-center gap-2">
                  {selectable && (
                    <Checkbox
                      checked={selected.has(a)}
                      onCheckedChange={(v) => onToggle([a], v === true)}
                      aria-label={t(`${K}.selectOne`, 'Select {address}', { address: a })}
                    />
                  )}
                  <code className="break-all font-mono text-xs" data-testid="decide-address">
                    {a}
                  </code>
                </div>
                {(item?.ports ?? []).length > 0 && (
                  <span className="text-xs text-muted-foreground">
                    {t('attackSurface.decide.seenPorts', 'Open ports seen: {ports}', {
                      ports: (item?.ports ?? []).join(', '),
                    })}
                  </span>
                )}
                {canAdd && (
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 self-start sm:self-auto"
                    onClick={() => onAdd([a], [])}
                    aria-label={t('attackSurface.decide.addOneLabel', 'Add {address} to scope', {
                      address: a,
                    })}
                  >
                    {g.shared
                      ? t(`${K}.addAnyway`, 'Add anyway')
                      : t('attackSurface.decide.addOne', 'Add')}
                  </Button>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </li>
  )
}
