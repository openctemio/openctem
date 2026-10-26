'use client'

/**
 * Triage after the fact, in bulk (research/124, RFC-054 §15).
 *
 * - "Mark out of scope" either excludes the selection from scanning (scope
 *   exclusions, exact or by rule, with a preview of what each would match),
 *   or marks it not ours (attribution "rejected").
 * - "Archive" hides the selection from the default list.
 *
 * Every action answers with a toast that offers Undo: deleting the
 * exclusions it added (the client asks for re-authentication, because that
 * widens scope), forgetting the "not ours" decision, or making the assets
 * active again. The server decides everything; the buttons only show for
 * the permission each action needs.
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
  type ExclusionPreviewItem,
} from '../../api/triage-api'
import { exactExclusions, ruleProposals } from '../../lib/out-of-scope-rules'
import type { Asset } from '../../types/asset.types'

type Mode = 'exclude' | 'reject'
type Granularity = 'exact' | 'rule'

const keyOf = (i: ExclusionItem) => `${i.exclusion_type}:${i.pattern}`
const SHOWN = 8

interface ActionProps {
  selected: Asset[]
  /** Refresh the list and clear the selection. */
  onDone?: () => void
}

export function MarkOutOfScopeAction({ selected, onDone }: ActionProps) {
  const { t } = useTranslation()
  const canExclude = useHasPermission(Permission.ScopeWrite)
  const canReject = useHasPermission(Permission.AssetsWrite)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [mode, setMode] = useState<Mode>(canExclude ? 'exclude' : 'reject')
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

  const items: ExclusionItem[] =
    granularity === 'exact'
      ? exact.items
      : rules.filter((r) => chosenRules.has(keyOf(r.item))).map((r) => r.item)

  // The preview: what each candidate exclusion would match now.
  useEffect(() => {
    if (!open || mode !== 'exclude') return
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
  }, [open, mode, exact.items, rules])

  if (!canExclude && !canReject) return null

  const matchedTotal = items.reduce((n, i) => n + (preview[keyOf(i)]?.matched ?? 0), 0)
  const tooMany =
    mode === 'exclude' ? items.length > MAX_BULK_EXCLUSIONS : selected.length > MAX_BULK_EXCLUSIONS

  const exclude = async () => {
    const res = await createExclusions(items)
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
    show(text, {
      duration: UNDO_TOAST_MS,
      action:
        ids.length > 0
          ? {
              label: t('assets.triage.undo', 'Undo'),
              onClick: () => {
                deleteExclusions(ids)
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
      if (mode === 'exclude') await exclude()
      else await reject()
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
                'Out of scope assets are never scanned actively. They stay in the inventory with their history unless you mark them not yours.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4 text-sm">
            <RadioGroup
              value={mode}
              onValueChange={(v) => setMode(v as Mode)}
              aria-label={t('assets.triage.modeLabel', 'How')}
            >
              {canExclude && (
                <div className="flex items-start gap-2">
                  <RadioGroupItem value="exclude" id="oos-exclude" />
                  <Label htmlFor="oos-exclude" className="grid gap-0.5 font-normal">
                    <span className="font-medium">
                      {t('assets.triage.exclude.label', 'Exclude from scanning')}
                    </span>
                    <span className="text-muted-foreground">
                      {t(
                        'assets.triage.exclude.hint',
                        'Adds scope exclusions. Exclusions win over every scope entry.'
                      )}
                    </span>
                  </Label>
                </div>
              )}
              {canReject && (
                <div className="flex items-start gap-2">
                  <RadioGroupItem value="reject" id="oos-reject" />
                  <Label htmlFor="oos-reject" className="grid gap-0.5 font-normal">
                    <span className="font-medium">
                      {t('assets.triage.reject.label', 'Not ours')}
                    </span>
                    <span className="text-muted-foreground">
                      {t(
                        'assets.triage.reject.hint',
                        'Records that these are not your organization’s. Names found again under them stay out too.'
                      )}
                    </span>
                  </Label>
                </div>
              )}
            </RadioGroup>

            {mode === 'exclude' && (
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
                    <RadioGroupItem value="rule" id="oos-rule" disabled={rules.length === 0} />
                    <Label htmlFor="oos-rule" className="font-normal">
                      {t('assets.triage.exclude.byRule', 'By rule ({count})', {
                        count: rules.length,
                      })}
                    </Label>
                  </div>
                </RadioGroup>

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
                              {matchText(r.item) ? `, ${matchText(r.item)}` : ''}
                            </span>
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
            {tooMany && (
              <p className="text-destructive">
                {t('assets.triage.tooMany', 'Select at most {max} at once.', {
                  max: MAX_BULK_EXCLUSIONS,
                })}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button
              onClick={() => void submit()}
              disabled={busy || tooMany || (mode === 'exclude' && items.length === 0)}
            >
              {busy
                ? t('assets.triage.saving', 'Saving…')
                : mode === 'exclude'
                  ? t('assets.triage.exclude.confirm', 'Exclude')
                  : t('assets.triage.reject.confirm', 'Mark not ours')}
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
