'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { Check, Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useDecideReviewBatch } from '@/features/attack-surface/hooks/use-easm-review'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'

interface ConfirmOwnershipActionProps {
  /** The skipped names the group lists (the platform confirms them by name). */
  names: string[]
  /** Called after the decision was saved (the caller refreshes its view). */
  onDone?: () => void
}

/**
 * Confirms the ownership of the assets a skipped-targets group lists in one
 * step: POST /api/v1/easm/candidates/decisions with state `confirmed`. It is
 * the same decision, permission (assets:write), data scope and audit as
 * confirming one asset on its Ownership tab. Shown only to a caller who may
 * confirm.
 */
export function ConfirmOwnershipAction({ names, onDone }: ConfirmOwnershipActionProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { decide, saving } = useDecideReviewBatch()
  const [done, setDone] = useState(false)
  if (!can(Permission.AssetsWrite) || names.length === 0) return null

  const confirm = async () => {
    try {
      const res = await decide([], 'confirmed', undefined, names)
      const decided = res.decided?.length ?? 0
      const missed = res.not_found?.length ?? 0
      if (decided > 0) {
        toast.success(t('scans.targetOutcome.confirm.done', undefined, { count: decided }))
        setDone(true)
        onDone?.()
      }
      if (missed > 0) {
        toast.warning(t('scans.targetOutcome.confirm.notFound', undefined, { count: missed }))
      }
    } catch (e) {
      toast.error(getErrorMessage(e, t('scans.targetOutcome.confirm.failed')))
    }
  }

  return (
    <div className="space-y-1" data-testid="confirm-ownership">
      <Button type="button" variant="outline" size="sm" onClick={confirm} disabled={saving || done}>
        {saving ? (
          <Loader2 className="me-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
        ) : (
          <Check className="me-1.5 h-3.5 w-3.5" aria-hidden />
        )}
        {t('scans.targetOutcome.confirm.action', undefined, { count: names.length })}
      </Button>
      <p className="text-xs text-muted-foreground">{t('scans.targetOutcome.confirm.hint')}</p>
    </div>
  )
}
