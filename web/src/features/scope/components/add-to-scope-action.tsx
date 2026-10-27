'use client'

/**
 * "Add to scope" for a selection of inventory assets (RFC-054 §14): one
 * request (POST /scope/targets/bulk) adds an exact entry per asset, with one
 * step-up for the batch (the shared client opens the dialog and retries).
 * The confirmation lists what will be added and what is skipped; the result
 * says what was added, what was already in scope and what was refused. The
 * server decides everything; the button only shows for scope:write.
 */

import { useMemo, useState } from 'react'
import { Crosshair } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'
import { createScopeTargetsBulk, invalidateScopeCache } from '../api/use-scope-api'
import type { ApiBulkScopeTargetsResponse } from '../api/scope-api.types'
import { scopeItemsForAssets, type ScopeSkipReason } from '../lib/scope-from-asset'

const SHOWN = 8
const MAX_ITEMS = 200

interface AddToScopeActionProps {
  /** Names of the selected assets. */
  names: string[]
  /** Called after entries were added (refresh the list, clear the selection). */
  onDone?: () => void
}

export function AddToScopeAction({ names, onDone }: AddToScopeActionProps) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const { items, skipped } = useMemo(() => scopeItemsForAssets(names), [names])
  const tooMany = items.length > MAX_ITEMS

  if (!canWrite) return null

  const skipText = (Object.entries(skipped) as [ScopeSkipReason, number][])
    .map(([reason, count]) => t(`scope.bulk.skip.${reason}`, '{count} skipped', { count }))
    .join(', ')

  const submit = async () => {
    setBusy(true)
    try {
      const res: ApiBulkScopeTargetsResponse = await createScopeTargetsBulk({ items })
      reportBulkResult(t, res)
      await invalidateScopeCache()
      setOpen(false)
      if ((res.created ?? 0) > 0) onDone?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scope.bulk.failed', 'Could not add to scope')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        <Crosshair className="me-2 h-4 w-4" aria-hidden />
        {t('scope.bulk.action', 'Add to scope')}
      </Button>
      <Dialog open={open} onOpenChange={(o) => !busy && setOpen(o)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('scope.bulk.title', 'Add {count} to scope', { count: items.length })}
            </DialogTitle>
            <DialogDescription>
              {t(
                'scope.bulk.description',
                'Each name or address becomes an exact scope entry, so scans may reach it. Exclusions still win, and anything already in scope is left as it is.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3 text-sm">
            {items.length > 0 ? (
              <ul className="space-y-1 font-mono text-xs" data-testid="add-to-scope-list">
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
            ) : (
              <p className="text-muted-foreground">
                {t('scope.bulk.nothing', 'None of the selected assets needs a scope entry.')}
              </p>
            )}
            {skipText && <p className="text-muted-foreground">{skipText}</p>}
            {tooMany && (
              <p className="text-destructive">
                {t('scope.bulk.tooMany', 'Select at most {max} at once.', { max: MAX_ITEMS })}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={() => void submit()} disabled={busy || items.length === 0 || tooMany}>
              {busy ? t('scope.bulk.adding', 'Adding…') : t('scope.bulk.confirm', 'Add to scope')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

type TFn = ReturnType<typeof useTranslation>['t']

/** One toast that says what the batch did. */
export function reportBulkResult(t: TFn, res: ApiBulkScopeTargetsResponse) {
  const created = res.created ?? 0
  const existing = res.existing ?? 0
  const refused = res.refused ?? 0
  const parts: string[] = []
  if (created > 0) parts.push(t('scope.bulk.created', '{count} added', { count: created }))
  if (existing > 0)
    parts.push(t('scope.bulk.existing', '{count} already in scope', { count: existing }))
  if (refused > 0) {
    const first = (res.results ?? []).find((r) => r.result === 'refused')
    const why = first?.message ? ` (${first.pattern}: ${first.message})` : ''
    parts.push(t('scope.bulk.refused', '{count} refused', { count: refused }) + why)
  }
  const text = parts.join(', ')
  if (refused > 0 && created === 0) toast.error(text)
  else if (refused > 0) toast.warning(text)
  else toast.success(text)
}
