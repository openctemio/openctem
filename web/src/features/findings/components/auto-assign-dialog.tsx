'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogBody,
} from '@/components/ui/alert-dialog'
import { Loader2, Users } from 'lucide-react'
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
  const [result, setResult] = useState<AutoAssignResult | null>(null)

  const handleAssign = async () => {
    setIsSubmitting(true)
    try {
      const data = await post<AutoAssignResult>('/api/v1/findings/actions/assign-to-owners', {
        filter: {
          // Assign unassigned critical+high findings
        },
      })

      setResult(data)

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
      setResult(null)
    } catch (error) {
      toast.error(getErrorMessage(error, t('findings.autoAssign.failed', 'Failed to auto-assign')))
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            {t('findings.autoAssign.title', 'Auto-Assign to Asset Owners')}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {t(
              'findings.autoAssign.description',
              'This will assign unassigned findings to their asset owners. Findings that already have an assignee will not be changed. Assets without an owner will be skipped.'
            )}
          </AlertDialogDescription>
        </AlertDialogHeader>

        <AlertDialogBody>
          {result && (
            <div className="rounded-lg border bg-muted/50 p-3 my-2 space-y-2">
              <p className="text-sm font-medium">
                {t('findings.autoAssign.assigned', '{count} findings assigned', {
                  count: result.assigned,
                })}
              </p>
              {Object.entries(result.by_owner).length > 0 && (
                <div className="text-xs text-muted-foreground space-y-0.5">
                  {Object.entries(result.by_owner)
                    .sort(([, a], [, b]) => b - a)
                    .slice(0, 10)
                    .map(([owner, count]) => (
                      <div key={owner}>
                        {t('findings.autoAssign.ownerCount', '{owner}: {count} findings', {
                          owner,
                          count,
                        })}
                      </div>
                    ))}
                </div>
              )}
              {result.unassigned > 0 && (
                <p className="text-xs text-warning">
                  {t('findings.autoAssign.skipped', '{count} findings skipped (no asset owner)', {
                    count: result.unassigned,
                  })}
                </p>
              )}
            </div>
          )}
        </AlertDialogBody>

        <AlertDialogFooter>
          <AlertDialogCancel disabled={isSubmitting}>
            {t('common.cancel', 'Cancel')}
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => {
              e.preventDefault()
              handleAssign()
            }}
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <>
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
                {t('findings.autoAssign.assigning', 'Assigning...')}
              </>
            ) : (
              t('findings.autoAssign.submit', 'Auto-Assign')
            )}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

export default AutoAssignDialog
