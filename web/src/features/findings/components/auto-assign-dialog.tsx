'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { post } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'

interface AutoAssignResult {
  assigned: number
  by_owner: Record<string, number>
  unassigned: number
}

interface AutoAssignDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

export function AutoAssignDialog({ open, onOpenChange, onSuccess }: AutoAssignDialogProps) {
  const { t } = useTranslation()
  const [isSubmitting, setIsSubmitting] = useState(false)

  const handleAssign = async () => {
    setIsSubmitting(true)
    try {
      const data = await post<AutoAssignResult>('/api/v1/findings/actions/assign-to-owners', {
        filter: {
          // Assign unassigned critical+high findings
        },
      })

      const ownerCount = Object.keys(data.by_owner).length
      toast.success(
        ownerCount === 1
          ? t('findings.autoAssign.successOne', '{count} findings assigned to {owners} owner', {
              count: data.assigned,
              owners: ownerCount,
            })
          : t('findings.autoAssign.successMany', '{count} findings assigned to {owners} owners', {
              count: data.assigned,
              owners: ownerCount,
            }),
        {
          description:
            data.unassigned > 0
              ? t('findings.autoAssign.noOwner', '{count} findings have no asset owner', {
                  count: data.unassigned,
                })
              : undefined,
        }
      )

      onSuccess?.()
      onOpenChange(false)
    } catch (error) {
      toast.error(getErrorMessage(error, t('findings.autoAssign.failed', 'Failed to auto-assign')))
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('findings.autoAssign.title', 'Assign unassigned findings to their asset owners?')}
      desc={t(
        'findings.autoAssign.description',
        'Every unassigned finding is assigned to the owner of its asset. Findings that already have an assignee stay as they are, and findings on assets without an owner are skipped.'
      )}
      confirmText={
        isSubmitting ? (
          <>
            <Loader2 className="me-2 h-4 w-4 animate-spin" />
            {t('findings.autoAssign.assigning', 'Assigning...')}
          </>
        ) : (
          t('findings.autoAssign.submit', 'Assign to owners')
        )
      }
      isLoading={isSubmitting}
      handleConfirm={handleAssign}
    />
  )
}

export default AutoAssignDialog
