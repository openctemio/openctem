'use client'

/**
 * "Add the missing targets to scope" for a scan review (RFC-054 §14, R6):
 * the targets the scope check refused with no_entry become exact scope
 * entries in one POST /scope/targets/bulk request (origin refusal_fix, one
 * step-up). The caller runs the check again afterwards (onAdded). Shown only
 * to callers who may add entries directly.
 */

import { useMemo, useState } from 'react'
import { Plus } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'
import { createScopeTargetsBulk, invalidateScopeCache } from '../api/use-scope-api'
import { scopeItemsForAssets } from '../lib/scope-from-asset'
import { reportBulkResult } from './add-to-scope-action'

interface AddMissingToScopeButtonProps {
  /** The refused targets (no_entry) as typed. */
  targets: string[]
  /** Called after entries were added (run the scope check again). */
  onAdded?: () => void
}

export function AddMissingToScopeButton({ targets, onAdded }: AddMissingToScopeButtonProps) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const [busy, setBusy] = useState(false)
  const { items } = useMemo(() => scopeItemsForAssets(targets), [targets])
  if (!canWrite || items.length === 0) return null

  const add = async () => {
    setBusy(true)
    try {
      const res = await createScopeTargetsBulk({
        items: items.slice(0, 200),
        origin: 'refusal_fix',
      })
      reportBulkResult(t, res)
      await invalidateScopeCache()
      if ((res.created ?? 0) + (res.existing ?? 0) > 0) onAdded?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scope.bulk.failed', 'Could not add to scope')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Button size="sm" variant="outline" onClick={() => void add()} disabled={busy}>
      <Plus className="me-2 h-4 w-4" aria-hidden />
      {busy
        ? t('scope.bulk.adding', 'Adding…')
        : t('scope.missing.add', 'Add {count} to scope', { count: items.length })}
    </Button>
  )
}
