'use client'

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
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
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useRequestApproval } from '../api/use-findings-api'
import { FINDING_STATUS_CONFIG } from '../types'
import type { FindingStatus } from '../types'
import { PERSON_CLOSURE_REASONS, closureReasonLabel } from '../lib/closure'

/** Days an accepted risk lasts unless the requester picks another date. */
const DEFAULT_ACCEPTANCE_DAYS = 90

/** Local calendar date (YYYY-MM-DD) `days` days and `years` years from today. */
function acceptanceDate(days: number, years = 0): string {
  const d = new Date()
  d.setFullYear(d.getFullYear() + years)
  d.setDate(d.getDate() + days)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

interface ApprovalDialogProps {
  findingId: string
  targetStatus: FindingStatus
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Called after an approval request is submitted successfully (e.g. to refresh lists/history) */
  onSuccess?: () => void | Promise<void>
}

export function ApprovalDialog({
  findingId,
  targetStatus,
  open,
  onOpenChange,
  onSuccess,
}: ApprovalDialogProps) {
  const { t } = useTranslation()
  const [justification, setJustification] = useState('')
  // Why the finding is not a risk to fix: a VEX-aligned code the server
  // requires and stores as the closure reason.
  const [reason, setReason] = useState('')
  const reasons = PERSON_CLOSURE_REASONS[targetStatus] ?? []
  // An accepted risk always ends: 90 days ahead unless changed, at most a year.
  const [expiresAt, setExpiresAt] = useState(() => acceptanceDate(DEFAULT_ACCEPTANCE_DAYS))
  const [step, setStep] = useState<'input' | 'confirm'>('input')
  const { trigger: requestApproval, isMutating } = useRequestApproval(findingId)

  const statusConfig = FINDING_STATUS_CONFIG[targetStatus]
  const statusLabel = statusConfig ? t(statusConfig.labelKey, statusConfig.label) : targetStatus
  const showExpiryPicker = targetStatus === 'accepted'
  const minDate = acceptanceDate(1)
  const maxDate = acceptanceDate(0, 1)
  const expiryValid =
    !showExpiryPicker || (!!expiresAt && expiresAt >= minDate && expiresAt <= maxDate)
  const justificationRequired = t(
    'findings.approvalDialog.justificationRequired',
    'Justification is required'
  )

  const reasonRequired = t('findings.approvalDialog.reasonRequired', 'Choose a reason')

  const handleNext = () => {
    if (!reason) {
      toast.error(reasonRequired)
      return
    }
    if (!justification.trim()) {
      toast.error(justificationRequired)
      return
    }
    if (!expiryValid) {
      toast.error(
        t('findings.approvalDialog.expiryInvalid', 'Choose an expiry date within the next year')
      )
      return
    }
    setStep('confirm')
  }

  const handleBack = () => {
    setStep('input')
  }

  const handleSubmit = async () => {
    if (!justification.trim()) {
      toast.error(justificationRequired)
      return
    }

    try {
      await requestApproval({
        requested_status: targetStatus,
        justification: justification.trim(),
        closure_reason: reason,
        ...(showExpiryPicker && expiresAt
          ? { expires_at: new Date(`${expiresAt}T00:00:00`).toISOString() }
          : {}),
      })
      toast.success(
        t('findings.approvalDialog.submitted', 'Approval request submitted for "{status}"', {
          status: statusLabel,
        })
      )
      setJustification('')
      setReason('')
      setExpiresAt(acceptanceDate(DEFAULT_ACCEPTANCE_DAYS))
      setStep('input')
      onOpenChange(false)
      await onSuccess?.()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('findings.approvalDialog.submitFailed', 'Failed to submit approval request')
        )
      )
    }
  }

  const handleOpenChange = (isOpen: boolean) => {
    if (!isOpen) {
      setStep('input')
    }
    onOpenChange(isOpen)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent size="sm">
        {step === 'input' ? (
          <>
            <DialogHeader>
              <DialogTitle>
                {t('findings.approvalDialog.title', 'Request Status Approval')}
              </DialogTitle>
              <DialogDescription>
                {t('findings.approvalDialog.descriptionBefore', 'Changing status to')}{' '}
                <strong>{statusLabel}</strong>{' '}
                {t(
                  'findings.approvalDialog.descriptionAfter',
                  'requires approval. Please provide a justification.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <div className="grid gap-4 py-4">
                <div className="grid gap-2">
                  <Label htmlFor="closure-reason">
                    {t('findings.approvalDialog.reason', 'Reason')}
                  </Label>
                  <Select value={reason} onValueChange={setReason}>
                    <SelectTrigger id="closure-reason">
                      <SelectValue
                        placeholder={t(
                          'findings.approvalDialog.reasonPlaceholder',
                          'Choose a reason'
                        )}
                      />
                    </SelectTrigger>
                    <SelectContent>
                      {reasons.map((r) => (
                        <SelectItem key={r} value={r}>
                          {closureReasonLabel(t, r)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="justification">
                    {t('findings.approvalDialog.justification', 'Justification')}
                  </Label>
                  <Textarea
                    id="justification"
                    placeholder={t(
                      'findings.approvalDialog.justificationPlaceholder',
                      'Explain why this status change is needed...'
                    )}
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    rows={4}
                    maxLength={2000}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t('findings.approvalDialog.characters', '{count}/2000 characters', {
                      count: justification.length,
                    })}
                  </p>
                </div>
                {showExpiryPicker && (
                  <div className="grid gap-2">
                    <Label htmlFor="expires-at">
                      {t('findings.approvalDialog.expiry', 'Acceptance expires on')}
                    </Label>
                    <Input
                      id="expires-at"
                      type="date"
                      required
                      value={expiresAt}
                      onChange={(e) => setExpiresAt(e.target.value)}
                      min={minDate}
                      max={maxDate}
                    />
                    <p className="text-xs text-muted-foreground">
                      {t(
                        'findings.approvalDialog.expiryHint',
                        'The finding reopens on this date. At most one year ahead.'
                      )}
                    </p>
                  </div>
                )}
              </div>
            </DialogBody>
            <DialogFooter>
              <Button variant="outline" onClick={() => handleOpenChange(false)}>
                {t('findings.approvalDialog.cancel', 'Cancel')}
              </Button>
              <Button
                onClick={handleNext}
                disabled={!reason || !justification.trim() || !expiryValid}
              >
                {t('findings.approvalDialog.review', 'Review')}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>
                {t('findings.approvalDialog.confirmTitle', 'Confirm Approval Request')}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'findings.approvalDialog.confirmDescription',
                  'Please review the details before submitting.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <div className="grid gap-3 py-4 text-sm">
                <div>
                  <span className="font-medium text-muted-foreground">
                    {t('findings.approvalDialog.status', 'Status:')}
                  </span>{' '}
                  <strong>{statusLabel}</strong>
                </div>
                {reason && (
                  <div>
                    <span className="font-medium text-muted-foreground">
                      {t('findings.approvalDialog.reasonLabel', 'Reason:')}
                    </span>{' '}
                    {closureReasonLabel(t, reason)}
                  </div>
                )}
                <div>
                  <span className="font-medium text-muted-foreground">
                    {t('findings.approvalDialog.justificationLabel', 'Justification:')}
                  </span>
                  <p className="mt-1 rounded-md border bg-muted/50 p-2 text-sm">{justification}</p>
                </div>
                {showExpiryPicker && expiresAt && (
                  <div>
                    <span className="font-medium text-muted-foreground">
                      {t('findings.approvalDialog.expires', 'Expires:')}
                    </span>{' '}
                    {new Date(`${expiresAt}T00:00:00`).toLocaleDateString()}
                  </div>
                )}
              </div>
            </DialogBody>
            <DialogFooter>
              <Button variant="outline" onClick={handleBack} disabled={isMutating}>
                {t('findings.approvalDialog.back', 'Back')}
              </Button>
              <Button onClick={handleSubmit} disabled={isMutating}>
                {isMutating
                  ? t('findings.approvalDialog.submitting', 'Submitting...')
                  : t('findings.approvalDialog.submit', 'Submit for Approval')}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
