'use client'

/**
 * Mark out of scope (research/320, RFC-054 §15 and §20), from the inventory
 * (bulk) and an asset's page.
 *
 * - Why: Not ours, Retired or Do not scan. Every kind stops scanning; a
 *   permanent Not ours or Retired exclusion also closes the open findings of
 *   what it matches as "Asset out of scope" (reopened on re-include). Do not
 *   scan, and anything with an end date, only stops scanning.
 * - For how long: until re-included, or until a date.
 * - Apply to: exactly the selection, or a rule (parent domain, /24), with a
 *   preview of what each would match and the findings it would close.
 *
 * With scope:write it adds scope exclusions of that kind; Not ours exactly
 * on the selection also records the "not ours" decision (assets:write) so
 * discovery stops offering the names again. With only assets:write it
 * records the decision alone. Every action answers with Undo; deleting
 * exclusions widens scope, so the client asks for re-authentication, and a
 * caller without scope:delete is told who can re-include instead. The server
 * decides everything; the buttons only show for the permission each needs.
 */

import { useEffect, useMemo, useState } from 'react'
import { Archive, Ban } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { UNDO_TOAST_MS, undoToast } from '@/lib/undo-toast'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  createExclusions,
  decideAttribution,
  deleteExclusions,
  MAX_BULK_EXCLUSIONS,
  MAX_BULK_STATUS,
  previewExclusions,
  setAssetsStatus,
  type ExclusionItem,
  type ExclusionKind,
  type ExclusionPreviewItem,
} from '../../api/triage-api'
import { exactExclusions, ruleProposals } from '../../lib/out-of-scope-rules'
import type { Asset } from '../../types/asset.types'

type Granularity = 'exact' | 'rule'
type Duration = 'permanent' | 'until'

const keyOf = (i: ExclusionItem) => `${i.exclusion_type}:${i.pattern}`
const SHOWN = 8
const KINDS: ExclusionKind[] = ['not_ours', 'retired', 'do_not_scan']
const DAY_MS = 24 * 60 * 60 * 1000

/** yyyy-mm-dd of a date in local time, for a date input. */
function dateValue(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

interface ActionProps {
  selected: Asset[]
  /** Refresh the list and clear the selection. */
  onDone?: () => void
}

export function MarkOutOfScopeAction({ selected, onDone }: ActionProps) {
  const { t } = useTranslation()
  const canExclude = useHasPermission(Permission.ScopeWrite)
  const canReject = useHasPermission(Permission.AssetsWrite)
  const canUndoExclusions = useHasPermission(Permission.ScopeDelete)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [kind, setKind] = useState<ExclusionKind>('not_ours')
  const [duration, setDuration] = useState<Duration>('permanent')
  const [until, setUntil] = useState(() => dateValue(new Date(Date.now() + 7 * DAY_MS)))
  // The first day an end date may be (tomorrow), fixed when the dialog mounts.
  const [minUntil] = useState(() => dateValue(new Date(Date.now() + DAY_MS)))
  const [reason, setReason] = useState('')
  const [granularity, setGranularity] = useState<Granularity>('exact')
  const names = useMemo(() => selected.map((a) => a.name), [selected])
  const exact = useMemo(() => exactExclusions(names), [names])
  const rules = useMemo(() => ruleProposals(names), [names])
  const [chosenRules, setChosenRules] = useState<Set<string>>(new Set())
  const [preview, setPreview] = useState<Record<string, ExclusionPreviewItem>>({})
  const [previewing, setPreviewing] = useState(false)

  // No rule is chosen by default: a parent domain may also hold in-scope
  // names, so a person picks each rule after reading its preview.
  useEffect(() => {
    setChosenRules(new Set())
  }, [rules])

  // A member with limited data access may close findings only with exact
  // rules: a rule that matches by wildcard or range would later reach assets
  // they cannot see (the server refuses it; the preview says so up front).
  const closesNow = canExclude && kind !== 'do_not_scan' && duration === 'permanent'
  const ruleBlocked =
    closesNow &&
    rules.length > 0 &&
    rules.every((r) => preview[keyOf(r.item)]?.closing_needs_full_access)
  useEffect(() => {
    if (ruleBlocked) setGranularity('exact')
  }, [ruleBlocked])

  const items: ExclusionItem[] =
    granularity === 'exact'
      ? exact.items
      : rules.filter((r) => chosenRules.has(keyOf(r.item))).map((r) => r.item)

  // The preview: what each candidate exclusion would match now.
  useEffect(() => {
    if (!open || !canExclude) return
    const all = [...exact.items, ...rules.map((r) => r.item)].slice(0, MAX_BULK_EXCLUSIONS)
    if (all.length === 0) return
    let live = true
    setPreviewing(true)
    previewExclusions(all)
      .then((res) => {
        if (!live) return
        const map: Record<string, ExclusionPreviewItem> = {}
        for (const p of res.items ?? []) map[keyOf(p)] = p
        setPreview(map)
      })
      .catch(() => {
        if (live) setPreview({})
      })
      .finally(() => {
        if (live) setPreviewing(false)
      })
    return () => {
      live = false
    }
  }, [open, canExclude, exact.items, rules])

  if (!canExclude && !canReject) return null

  // Without scope:write only the "not ours" decision is possible.
  const decisionOnly = !canExclude
  const effectiveKind: ExclusionKind = decisionOnly ? 'not_ours' : kind
  const permanent = decisionOnly || duration === 'permanent'
  const closes = effectiveKind !== 'do_not_scan' && permanent
  const matchedTotal = items.reduce((n, i) => n + (preview[keyOf(i)]?.matched ?? 0), 0)
  const findingsTotal = items.reduce((n, i) => n + (preview[keyOf(i)]?.open_findings ?? 0), 0)
  const tooMany = decisionOnly
    ? selected.length > MAX_BULK_EXCLUSIONS
    : items.length > MAX_BULK_EXCLUSIONS
  const untilInvalid = !permanent && (!until || until < minUntil)

  const exclude = async () => {
    const expiresAt = permanent ? undefined : new Date(`${until}T23:59:59`).toISOString()
    const res = await createExclusions(items, {
      kind: effectiveKind,
      expiresAt,
      reason: reason.trim() || undefined,
    })
    // "Not ours" on exactly the selection is also the decision, so
    // discovery stops offering these names again.
    let decided: string[] = []
    if (effectiveKind === 'not_ours' && permanent && granularity === 'exact' && canReject) {
      const d = await decideAttribution(
        selected.map((a) => a.id),
        'rejected'
      )
      decided = (d.decided ?? []).map((x) => x.asset_id)
    }
    const ids = res.results.filter((r) => r.result === 'created' && r.id).map((r) => r.id as string)
    const text = [
      t('assets.triage.exclude.created', '{count} exclusions added', { count: res.created }),
      res.existing > 0
        ? t('assets.triage.exclude.existing', '{count} already excluded', { count: res.existing })
        : '',
      res.refused > 0
        ? t('assets.triage.exclude.refused', '{count} refused', { count: res.refused })
        : '',
    ]
      .filter(Boolean)
      .join('. ')
    const show = res.refused > 0 && res.created === 0 ? toast.error : toast.success
    const undoable = ids.length > 0 || decided.length > 0
    show(text, {
      duration: UNDO_TOAST_MS,
      description:
        undoable && !canUndoExclusions && ids.length > 0
          ? t(
              'assets.triage.exclude.undoNeedsAdmin',
              'Re-including needs the scope delete permission: ask an administrator.'
            )
          : undefined,
      action:
        undoable && (canUndoExclusions || ids.length === 0)
          ? {
              label: t('assets.triage.undo', 'Undo'),
              onClick: () => {
                Promise.all([
                  ids.length > 0 ? deleteExclusions(ids) : Promise.resolve(),
                  decided.length > 0 ? decideAttribution(decided, 'automatic') : Promise.resolve(),
                ])
                  .then(() => {
                    toast.success(t('assets.triage.exclude.undone', 'Exclusions removed'))
                    onDone?.()
                  })
                  .catch((err) =>
                    toast.error(getErrorMessage(err, t('assets.triage.undoFailed', 'Undo failed')))
                  )
              },
            }
          : undefined,
    })
  }

  const reject = async () => {
    const ids = selected.map((a) => a.id)
    const res = await decideAttribution(ids, 'rejected')
    const decided = (res.decided ?? []).map((d) => d.asset_id)
    const rejectMessage = t('assets.triage.reject.done', '{count} marked not ours', {
      count: decided.length,
    })
    if (decided.length === 0) toast.success(rejectMessage)
    else
      undoToast({
        message: rejectMessage,
        t,
        undo: () => decideAttribution(decided, 'automatic'),
        undoneMessage: t('assets.triage.reject.undone', 'Decision undone'),
        failedMessage: t('assets.triage.undoFailed', 'Undo failed'),
        onUndone: onDone,
      })
  }

  const submit = async () => {
    setBusy(true)
    try {
      if (decisionOnly) await reject()
      else await exclude()
      setOpen(false)
      onDone?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('assets.triage.failed', 'Could not mark out of scope')))
    } finally {
      setBusy(false)
    }
  }

  const matchText = (i: ExclusionItem) => {
    const p = preview[keyOf(i)]
    if (!p) return previewing ? t('assets.triage.preview.loading', 'Checking…') : ''
    if (p.code) return p.message || t('assets.triage.preview.refused', 'Would be refused')
    return t('assets.triage.preview.matches', 'matches {count} assets', { count: p.matched })
  }

  const kindLabel = (k: ExclusionKind) =>
    ({
      not_ours: t('assets.triage.kind.notOurs', 'Not ours'),
      retired: t('assets.triage.kind.retired', 'Retired'),
      do_not_scan: t('assets.triage.kind.doNotScan', 'Do not scan'),
    })[k]
  const kindHint = (k: ExclusionKind) =>
    ({
      not_ours: t(
        'assets.triage.kind.notOursHint',
        'Someone else owns it: sold, a third party, a typo in an import.'
      ),
      retired: t('assets.triage.kind.retiredHint', 'It is gone and will not come back.'),
      do_not_scan: t(
        'assets.triage.kind.doNotScanHint',
        'Yours, but it must not be scanned: a fragile system, a legal hold.'
      ),
    })[k]

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        <Ban className="me-2 h-4 w-4" aria-hidden />
        {t('assets.triage.action', 'Mark out of scope')}
      </Button>
      <Dialog open={open} onOpenChange={(o) => !busy && setOpen(o)}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {t('assets.triage.title', 'Mark {count} out of scope', { count: selected.length })}
            </DialogTitle>
            <DialogDescription>
              {t(
                'assets.triage.description',
                'Out of scope assets are never scanned actively. They stay in the inventory with their history.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4 text-sm">
            {!decisionOnly && (
              <fieldset className="space-y-2">
                <legend className="font-medium">{t('assets.triage.kind.label', 'Why')}</legend>
                <RadioGroup
                  value={kind}
                  onValueChange={(v) => setKind(v as ExclusionKind)}
                  aria-label={t('assets.triage.kind.label', 'Why')}
                >
                  {KINDS.map((k) => (
                    <div key={k} className="flex items-start gap-2">
                      <RadioGroupItem value={k} id={`oos-kind-${k}`} />
                      <Label htmlFor={`oos-kind-${k}`} className="grid gap-0.5 font-normal">
                        <span className="font-medium">{kindLabel(k)}</span>
                        <span className="text-muted-foreground">{kindHint(k)}</span>
                      </Label>
                    </div>
                  ))}
                </RadioGroup>
              </fieldset>
            )}

            {!decisionOnly && (
              <fieldset className="space-y-2">
                <legend className="font-medium">
                  {t('assets.triage.duration.label', 'For how long')}
                </legend>
                <RadioGroup
                  value={duration}
                  onValueChange={(v) => setDuration(v as Duration)}
                  className="flex flex-wrap items-center gap-4"
                  aria-label={t('assets.triage.duration.label', 'For how long')}
                >
                  <div className="flex items-center gap-2">
                    <RadioGroupItem value="permanent" id="oos-permanent" />
                    <Label htmlFor="oos-permanent" className="font-normal">
                      {t('assets.triage.duration.permanent', 'Until re-included')}
                    </Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <RadioGroupItem value="until" id="oos-until" />
                    <Label htmlFor="oos-until" className="font-normal">
                      {t('assets.triage.duration.until', 'Until')}
                    </Label>
                    <Input
                      type="date"
                      className="h-8 w-40"
                      value={until}
                      min={minUntil}
                      disabled={duration !== 'until'}
                      onChange={(e) => setUntil(e.target.value)}
                      aria-label={t('assets.triage.duration.untilDate', 'End date')}
                    />
                  </div>
                </RadioGroup>
              </fieldset>
            )}

            {!decisionOnly && (
              <div className="space-y-3 rounded-md border p-3">
                <RadioGroup
                  value={granularity}
                  onValueChange={(v) => setGranularity(v as Granularity)}
                  className="flex flex-wrap gap-4"
                  aria-label={t('assets.triage.exclude.granularity', 'What to exclude')}
                >
                  <div className="flex items-center gap-2">
                    <RadioGroupItem value="exact" id="oos-exact" />
                    <Label htmlFor="oos-exact" className="font-normal">
                      {t('assets.triage.exclude.exact', 'Exactly these ({count})', {
                        count: exact.items.length,
                      })}
                    </Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <RadioGroupItem
                      value="rule"
                      id="oos-rule"
                      disabled={rules.length === 0 || ruleBlocked}
                    />
                    <Label htmlFor="oos-rule" className="font-normal">
                      {t('assets.triage.exclude.byRule', 'By rule ({count})', {
                        count: rules.length,
                      })}
                    </Label>
                  </div>
                </RadioGroup>

                {ruleBlocked && (
                  <p className="text-xs text-muted-foreground" data-testid="oos-rule-blocked">
                    {t(
                      'assets.triage.exclude.ruleNeedsFullAccess',
                      'A rule is unavailable for closing findings with limited data access: it would also reach assets you cannot see, now or later. Mark the assets exactly, or ask someone with full data access.'
                    )}
                  </p>
                )}
                {granularity === 'exact' ? (
                  <ul className="space-y-1 text-xs" data-testid="oos-exact-list">
                    {exact.items.slice(0, SHOWN).map((i) => (
                      <li key={keyOf(i)} className="flex flex-wrap justify-between gap-x-3">
                        <span className="truncate font-mono">{i.pattern}</span>
                        <span className="text-muted-foreground">{matchText(i)}</span>
                      </li>
                    ))}
                    {exact.items.length > SHOWN && (
                      <li className="text-muted-foreground">
                        {t('assets.triage.more', 'and {count} more', {
                          count: exact.items.length - SHOWN,
                        })}
                      </li>
                    )}
                  </ul>
                ) : (
                  <ul className="space-y-2 text-xs" data-testid="oos-rule-list">
                    {rules.map((r) => {
                      const k = keyOf(r.item)
                      const id = `oos-rule-${k}`
                      return (
                        <li key={k} className="flex items-start gap-2">
                          <Checkbox
                            id={id}
                            checked={chosenRules.has(k)}
                            onCheckedChange={(on) => {
                              const next = new Set(chosenRules)
                              if (on) next.add(k)
                              else next.delete(k)
                              setChosenRules(next)
                            }}
                          />
                          <Label htmlFor={id} className="grid gap-0.5 font-normal">
                            <span className="font-mono">{r.item.pattern}</span>
                            <span className="text-muted-foreground">
                              {t('assets.triage.rule.covers', 'covers {count} selected', {
                                count: r.covers,
                              })}
                            </span>
                            {matchText(r.item) && (
                              <span className="text-muted-foreground">{matchText(r.item)}</span>
                            )}
                          </Label>
                        </li>
                      )
                    })}
                  </ul>
                )}
                {exact.skipped > 0 && granularity === 'exact' && (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'assets.triage.exclude.skipped',
                      '{count} selected need no exclusion (internal names, repositories, cloud accounts).',
                      { count: exact.skipped }
                    )}
                  </p>
                )}
                {!previewing && items.length > 0 && (
                  <p className="text-xs" data-testid="oos-preview-total">
                    {t(
                      'assets.triage.preview.total',
                      'Together they match {count} assets you can see.',
                      { count: matchedTotal }
                    )}
                  </p>
                )}
              </div>
            )}

            <section className="space-y-1 rounded-md bg-muted/50 p-3" data-testid="oos-effects">
              <h3 className="font-medium">{t('assets.triage.effects.title', 'What happens')}</h3>
              <p>
                {t(
                  'assets.triage.effects.scans',
                  'Scans, coverage, retests and follow-ups stop for these targets.'
                )}
              </p>
              {closes ? (
                <p data-testid="oos-effects-findings">
                  {decisionOnly || previewing
                    ? t(
                        'assets.triage.effects.closeAny',
                        'Their open findings close as "Asset out of scope" (not counted as fixed), and their tasks, tickets and SLA clocks follow.'
                      )
                    : t(
                        'assets.triage.effects.close',
                        '{count} open findings close as "Asset out of scope" (not counted as fixed), and their tasks, tickets and SLA clocks follow.',
                        { count: findingsTotal }
                      )}
                </p>
              ) : (
                <p data-testid="oos-effects-findings">
                  {t('assets.triage.effects.keep', 'Their findings stay open.')}
                </p>
              )}
              <p className="text-muted-foreground">
                {permanent
                  ? t('assets.triage.effects.reinclude', 'Re-including them reopens what closed.')
                  : t(
                      'assets.triage.effects.resume',
                      'Scanning resumes by itself after the end date.'
                    )}
              </p>
            </section>

            {!decisionOnly && (
              <div className="space-y-1">
                <Label htmlFor="oos-reason">
                  {t('assets.triage.reason.label', 'Reason (optional)')}
                </Label>
                <Input
                  id="oos-reason"
                  value={reason}
                  maxLength={1000}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder={t('assets.triage.reason.placeholder', 'Sold in September')}
                />
              </div>
            )}
            {tooMany && (
              <p className="text-destructive">
                {t('assets.triage.tooMany', 'Select at most {max} at once.', {
                  max: MAX_BULK_EXCLUSIONS,
                })}
              </p>
            )}
            {untilInvalid && (
              <p className="text-destructive">
                {t('assets.triage.duration.invalid', 'Pick an end date after today.')}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button
              onClick={() => void submit()}
              disabled={busy || tooMany || untilInvalid || (!decisionOnly && items.length === 0)}
            >
              {busy
                ? t('assets.triage.saving', 'Saving…')
                : decisionOnly
                  ? t('assets.triage.reject.confirm', 'Mark not ours')
                  : t('assets.triage.confirm', 'Confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

/** Archive the selection (hide it from the default list), with Undo. */
export function ArchiveAssetsAction({ selected, onDone }: ActionProps) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.AssetsWrite)
  const [busy, setBusy] = useState(false)
  if (!canWrite) return null
  const ids = selected.map((a) => a.id)
  const tooMany = ids.length > MAX_BULK_STATUS

  const run = async () => {
    setBusy(true)
    try {
      const res = await setAssetsStatus(ids, 'archived')
      undoToast({
        message: t('assets.triage.archive.done', '{count} archived', { count: res.updated }),
        t,
        undo: () => setAssetsStatus(ids, 'active'),
        undoneMessage: t('assets.triage.archive.undone', 'Restored'),
        failedMessage: t('assets.triage.undoFailed', 'Undo failed'),
        onUndone: onDone,
      })
      onDone?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('assets.triage.archive.failed', 'Could not archive')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      disabled={busy || tooMany}
      title={
        tooMany
          ? t('assets.triage.archive.tooMany', 'Select at most {max} at once.', {
              max: MAX_BULK_STATUS,
            })
          : undefined
      }
      onClick={() => void run()}
    >
      <Archive className="me-2 h-4 w-4" aria-hidden />
      {t('assets.triage.archive.action', 'Archive')}
    </Button>
  )
}
