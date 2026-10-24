'use client'

import { useState } from 'react'
import type { BulkOutcome } from '../lib/bulk'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { BulkActionBar, GatedButton } from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Check, X, AlertTriangle, RefreshCw, ShieldCheck, ShieldX, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import type { ExposureEvent } from '@/lib/api/exposure-types'
import {
  resolveExposure,
  acceptExposure,
  markExposureFalsePositive,
  reactivateExposure,
} from '../hooks/use-exposures'

type ActionType = 'resolve' | 'accept' | 'false_positive' | 'reactivate'

/**
 * Accepting a risk and marking a false positive close an exposure without
 * fixing it, so the API requires findings:approve for them (api#675); resolve
 * and reactivate keep findings:write. Shown on the disabled actions.
 */
export const APPROVE_REQUIRED_REASON =
  'Accepting a risk or marking a false positive needs approval rights (findings:approve). Ask an owner or administrator.'

/** Whether the current user may accept risk / mark false positive. */
export function useCanApproveExposures(): boolean {
  return useHasPermission(Permission.FindingsApprove)
}

interface ExposureActionDialogProps {
  exposure: ExposureEvent | null
  actionType: ActionType | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

const actionConfig: Record<
  ActionType,
  {
    title: string
    description: string
    icon: typeof Check
    buttonText: string
    buttonVariant: 'default' | 'destructive' | 'outline' | 'secondary'
    successMessage: string
    requireReason: boolean
  }
> = {
  resolve: {
    title: 'Resolve exposure',
    description: 'Mark this exposure as resolved. This indicates the issue has been fixed.',
    icon: ShieldCheck,
    buttonText: 'Mark resolved',
    buttonVariant: 'default',
    successMessage: 'Exposure marked as resolved',
    requireReason: false,
  },
  accept: {
    title: 'Accept risk',
    description:
      'Accept the risk associated with this exposure. Use this when the exposure is a known acceptable risk.',
    icon: AlertTriangle,
    buttonText: 'Accept risk',
    buttonVariant: 'secondary',
    successMessage: 'Risk accepted',
    requireReason: true,
  },
  false_positive: {
    title: 'Mark as false positive',
    description:
      'Mark this exposure as a false positive. Use this when the detection was incorrect.',
    icon: ShieldX,
    buttonText: 'Mark false positive',
    buttonVariant: 'outline',
    successMessage: 'Marked as false positive',
    requireReason: true,
  },
  reactivate: {
    title: 'Reactivate exposure',
    description: 'Reactivate this exposure. This will return it to active status for remediation.',
    icon: RefreshCw,
    buttonText: 'Reactivate',
    buttonVariant: 'default',
    successMessage: 'Exposure reactivated',
    requireReason: false,
  },
}

/**
 * Exposure Action Dialog - Handles state transitions with optional reason
 */
export function ExposureActionDialog({
  exposure,
  actionType,
  open,
  onOpenChange,
  onSuccess,
}: ExposureActionDialogProps) {
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  if (!actionType || !exposure) return null

  const config = actionConfig[actionType]
  const Icon = config.icon

  const handleSubmit = async () => {
    if (config.requireReason && !reason.trim()) {
      toast.error('Please provide a reason')
      return
    }

    setIsSubmitting(true)
    try {
      const input = reason.trim() ? { reason: reason.trim() } : undefined

      let result: ExposureEvent | undefined
      switch (actionType) {
        case 'resolve':
          await resolveExposure(exposure.id, input)
          break
        case 'accept':
          result = await acceptExposure(exposure.id, input)
          break
        case 'false_positive':
          result = await markExposureFalsePositive(exposure.id, input)
          break
        case 'reactivate':
          await reactivateExposure(exposure.id)
          break
      }

      if (result?.pending_disposition) {
        // High or critical: a second approver must confirm.
        toast.info(
          t(
            'exposures.disposition.requestSent',
            'Request sent. A second approver must confirm before the exposure changes.'
          )
        )
      } else {
        toast.success(config.successMessage)
      }
      onOpenChange(false)
      setReason('')
      onSuccess?.()
    } catch (error) {
      toast.error(getErrorMessage(error, `Failed to ${actionType.replace('_', ' ')} exposure`))
      console.error(error)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-muted p-2 text-muted-foreground">
              <Icon className="h-5 w-5" />
            </div>
            <DialogTitle>{config.title}</DialogTitle>
          </div>
          <DialogDescription>{config.description}</DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4 py-4">
            <div className="rounded-lg border p-3 bg-muted/50">
              <p className="text-sm font-medium">{exposure.title}</p>
              <p className="text-xs text-muted-foreground mt-1">
                {exposure.description || 'No description'}
              </p>
            </div>

            {(config.requireReason || actionType !== 'reactivate') && (
              <div className="space-y-2">
                <Label htmlFor="reason">
                  Reason {config.requireReason ? '(required)' : '(optional)'}
                </Label>
                <Textarea
                  id="reason"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder={`Why are you ${actionType === 'resolve' ? 'resolving' : actionType === 'accept' ? 'accepting' : actionType === 'false_positive' ? 'marking as false positive' : 'reactivating'} this exposure?`}
                  rows={3}
                />
              </div>
            )}
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            variant={config.buttonVariant}
            onClick={handleSubmit}
            disabled={isSubmitting || (config.requireReason && !reason.trim())}
          >
            {isSubmitting && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {config.buttonText}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

interface ExposureQuickActionsProps {
  exposure: ExposureEvent
  onSuccess?: () => void
  className?: string
}

/**
 * Exposure Quick Actions - Inline action buttons for exposure state changes
 */
export function ExposureQuickActions({
  exposure,
  onSuccess,
  className,
}: ExposureQuickActionsProps) {
  const [actionType, setActionType] = useState<ActionType | null>(null)
  const canApprove = useCanApproveExposures()

  const isActive = exposure.state === 'active'

  return (
    <>
      <div className={cn('flex items-center gap-2', className)}>
        {isActive ? (
          <>
            <Button size="sm" variant="outline" onClick={() => setActionType('resolve')}>
              <Check className="me-1 h-4 w-4" />
              Resolve
            </Button>
            <GatedButton
              size="sm"
              variant="outline"
              allowed={canApprove}
              reason={APPROVE_REQUIRED_REASON}
              onClick={() => setActionType('accept')}
            >
              <AlertTriangle className="me-1 h-4 w-4" />
              Accept
            </GatedButton>
            <GatedButton
              size="sm"
              variant="outline"
              allowed={canApprove}
              reason={APPROVE_REQUIRED_REASON}
              onClick={() => setActionType('false_positive')}
            >
              <X className="me-1 h-4 w-4" />
              False positive
            </GatedButton>
          </>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setActionType('reactivate')}>
            <RefreshCw className="me-1 h-4 w-4" />
            Reactivate
          </Button>
        )}
      </div>

      <ExposureActionDialog
        exposure={exposure}
        actionType={actionType}
        open={actionType !== null}
        onOpenChange={(open) => !open && setActionType(null)}
        onSuccess={onSuccess}
      />
    </>
  )
}

interface ExposureBulkActionsProps {
  selectedIds: string[]
  onClearSelection: () => void
  /** Handlers never throw for a partial failure: they return what happened. */
  onBulkResolve: (ids: string[]) => Promise<BulkOutcome | void>
  onBulkAccept: (ids: string[], reason: string) => Promise<BulkOutcome | void>
  onBulkFalsePositive: (ids: string[], reason: string) => Promise<BulkOutcome | void>
}

/**
 * Exposure Bulk Actions - Actions for multiple selected exposures
 */
export function ExposureBulkActions({
  selectedIds,
  onClearSelection,
  onBulkResolve,
  onBulkAccept,
  onBulkFalsePositive,
}: ExposureBulkActionsProps) {
  const [isProcessing, setIsProcessing] = useState(false)
  const [bulkAction, setBulkAction] = useState<'accept' | 'false_positive' | null>(null)
  const [resolveOpen, setResolveOpen] = useState(false)
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const canApprove = useCanApproveExposures()

  const count = selectedIds.length

  if (count === 0) return null

  // One place owns every bulk toast: items that went to pending approval get
  // the approval notice and no success toast, failures say "x of N failed".
  const report = (outcome: BulkOutcome | void, doneKey: string, doneDefault: string) => {
    const o = outcome ?? { total: count, succeeded: count, pending: 0, failed: 0 }
    const applied = o.succeeded - o.pending
    if (applied > 0) toast.success(t(doneKey, doneDefault, { count: applied }))
    if (o.pending > 0) {
      toast.info(
        t(
          'exposures.disposition.bulkPending',
          '{count} high or critical exposures wait for a second approver.',
          { count: o.pending }
        )
      )
    }
    if (o.failed > 0) {
      toast.error(
        t('exposures.bulk.partialFailed', '{failed} of {total} failed.', {
          failed: o.failed,
          total: o.total,
        })
      )
    }
  }

  const handleBulkResolve = async () => {
    setIsProcessing(true)
    try {
      report(
        await onBulkResolve(selectedIds),
        'exposures.bulk.resolved',
        '{count} exposures resolved.'
      )
      setResolveOpen(false)
      onClearSelection()
    } catch (_error) {
      toast.error(t('exposures.bulk.resolveFailed', 'Could not resolve the exposures.'))
    } finally {
      setIsProcessing(false)
    }
  }

  const handleBulkActionSubmit = async () => {
    if (!reason.trim()) {
      toast.error(t('exposures.bulk.reasonRequired', 'Enter a reason.'))
      return
    }

    setIsProcessing(true)
    try {
      if (bulkAction === 'accept') {
        report(
          await onBulkAccept(selectedIds, reason),
          'exposures.bulk.accepted',
          '{count} exposures accepted.'
        )
      } else if (bulkAction === 'false_positive') {
        report(
          await onBulkFalsePositive(selectedIds, reason),
          'exposures.bulk.falsePositive',
          '{count} exposures marked as false positive.'
        )
      }
      onClearSelection()
      setBulkAction(null)
      setReason('')
    } catch (_error) {
      toast.error(t('exposures.bulk.updateFailed', 'Could not update the exposures.'))
    } finally {
      setIsProcessing(false)
    }
  }

  return (
    <>
      <BulkActionBar count={count} onClear={onClearSelection} noun="exposures selected">
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setResolveOpen(true)}
          disabled={isProcessing}
        >
          {isProcessing ? (
            <Loader2 className="me-2 h-4 w-4 animate-spin" />
          ) : (
            <Check className="me-2 h-4 w-4" />
          )}
          Resolve
        </Button>
        <GatedButton
          size="sm"
          variant="ghost"
          allowed={canApprove}
          reason={APPROVE_REQUIRED_REASON}
          onClick={() => setBulkAction('accept')}
          disabled={isProcessing}
        >
          <AlertTriangle className="me-2 h-4 w-4" />
          Accept risk
        </GatedButton>
        <GatedButton
          size="sm"
          variant="ghost"
          allowed={canApprove}
          reason={APPROVE_REQUIRED_REASON}
          onClick={() => setBulkAction('false_positive')}
          disabled={isProcessing}
        >
          <X className="me-2 h-4 w-4" />
          False positive
        </GatedButton>
      </BulkActionBar>

      <Dialog open={bulkAction !== null} onOpenChange={(open) => !open && setBulkAction(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {bulkAction === 'accept' ? 'Accept risk for ' : 'Mark as false positive: '}
              {count} exposure(s)
            </DialogTitle>
            <DialogDescription>
              Please provide a reason for this bulk action. This will be recorded in the audit log.
            </DialogDescription>
          </DialogHeader>

          <DialogBody>
            <div className="space-y-2 py-4">
              <Label htmlFor="bulk-reason">Reason (required)</Label>
              <Textarea
                id="bulk-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Provide a reason for this bulk action..."
                rows={3}
              />
            </div>
          </DialogBody>

          <DialogFooter>
            <Button variant="outline" onClick={() => setBulkAction(null)}>
              Cancel
            </Button>
            <Button onClick={handleBulkActionSubmit} disabled={!reason.trim() || isProcessing}>
              {isProcessing && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={resolveOpen}
        onOpenChange={(open) => !isProcessing && setResolveOpen(open)}
        title={
          count === 1
            ? t('confirm.exposure.bulkResolveTitleOne', 'Resolve 1 exposure?')
            : t('confirm.exposure.bulkResolveTitle', 'Resolve {count} exposures?', { count })
        }
        desc={t(
          'confirm.exposure.bulkResolveDesc',
          'The selected exposures are marked resolved and leave the active list. Reactivate one from its row if it is still present.'
        )}
        confirmText={t('confirm.exposure.resolve', 'Resolve')}
        isLoading={isProcessing}
        handleConfirm={handleBulkResolve}
      />
    </>
  )
}
