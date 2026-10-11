'use client'

/**
 * After a person confirms assets (RFC-054 §14.5), the API adds their exact
 * scope entries and says so in `scope`. Without a recent re-authentication it
 * adds nothing and lists the pending entries: this follow-up adds them with
 * POST /scope/targets/bulk, where the shared client asks for the step-up and
 * retries. Absent `scope` (Strict, the setting off): nothing to do.
 */

import { useCallback } from 'react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { createScopeTargetsBulk, invalidateScopeCache } from '../api/use-scope-api'
import type { ApiConfirmScopeCoverage } from '../api/scope-api.types'
import { reportBulkResult } from '../components/add-to-scope-action'

export function useConfirmScopeFollowUp() {
  const { t } = useTranslation()
  return useCallback(
    async (scope: ApiConfirmScopeCoverage | null | undefined) => {
      if (!scope) return
      if (scope.step_up_required && scope.pending && scope.pending.length > 0) {
        try {
          const items = scope.pending.flatMap((p) =>
            p.target_type && p.pattern ? [{ target_type: p.target_type, pattern: p.pattern }] : []
          )
          const res = await createScopeTargetsBulk({ items })
          reportBulkResult(t, res)
          await invalidateScopeCache()
        } catch (err) {
          toast.error(getErrorMessage(err, t('scope.bulk.failed', 'Could not add to scope')))
        }
        return
      }
      const added = scope.added ?? 0
      if (added > 0) {
        toast.success(t('scope.confirm.added', '{count} added to scope', { count: added }))
        await invalidateScopeCache()
      }
      if ((scope.refused ?? 0) > 0) {
        toast.warning(
          t('scope.confirm.refused', '{count} not added to scope: {reason}', {
            count: scope.refused ?? 0,
            reason: scope.refused_reason ?? '',
          })
        )
      }
    },
    [t]
  )
}
