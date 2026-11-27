'use client'

import { useEffect, useState } from 'react'
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
import { usePermissions } from '@/lib/permissions'
import { useFindingApprovalPolicy, useRequestApproval } from '../api/use-findings-api'
import { ApprovalEvaluationBanner } from './approval-evaluation-banner'
import { FINDING_STATUS_CONFIG } from '../types'
import type { ApiApproval, FindingStatus } from '../types'
import { PERSON_CLOSURE_REASONS, closureReasonLabel } from '../lib/closure'
import { formatDate } from '@/lib/app-locale'
import { noteMinLength, readLastReason, writeLastReason } from '../lib/approval-note'

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
  /**
   * The longest a risk on this finding may be accepted, in days (the API's
   * rule by priority: P0 or KEV 30, P1 90, P2 180, P3 365). The date picker
   * stops there and the default end never passes it.
   */
  maxAcceptanceDays?: number
  /**
   * Called after an approval request is submitted successfully (e.g. to
   * refresh lists/history), with the API's answer: a pending request, or an
   * approved one (`single_person`) when the person decided alone.
   */
  onSuccess?: (result?: ApiApproval & { single_person?: boolean }) => void | Promise<void>
  /**
   * A note to start from (triage's AI suggestion). Only fills the form: the
   * person still picks the reason, edits the note and sends the request.
   */
  initialJustification?: string
}

export function ApprovalDialog({
  findingId,
  targetStatus,
  open,
  onOpenChange,
  onSuccess,
  maxAcceptanceDays,
  initialJustification,
}: ApprovalDialogProps) {
  const { t } = useTranslation()
  // How a request of this status would be decided now: the tier and why, who
  // may approve, the longest acceptance and the shortest note.
  const isFalsePositive = targetStatus === 'false_positive'
  const policyStatus = targetStatus === 'accepted' ? 'accepted' : 'false_positive'
  const { data: fpPolicy } = useFindingApprovalPolicy(
    findingId,
    policyStatus,
    open && (isFalsePositive || targetStatus === 'accepted')
  )
  const evaluation = fpPolicy?.evaluation
  const propCap = maxAcceptanceDays && maxAcceptanceDays > 0 ? maxAcceptanceDays : 365
  const policyCap = evaluation?.max_acceptance_days ?? 0
  const capDays = policyCap > 0 ? Math.min(propCap, policyCap) : propCap
  const defaultDays = Math.min(DEFAULT_ACCEPTANCE_DAYS, capDays)
  // The note is optional only when the caller decides alone on a finding
  // that is not serious; otherwise it is required (the server checks again).
  const minNote = noteMinLength(isFalsePositive || targetStatus === 'accepted' ? fpPolicy : null)
  const noteOptional = minNote === 0
  const { isOwner } = usePermissions()
  const [justification, setJustification] = useState(initialJustification ?? '')
  // Why the finding is not a risk to fix: a VEX-aligned code the server
  // requires and stores as the closure reason.
  const [reason, setReason] = useState('')
  const reasons = PERSON_CLOSURE_REASONS[targetStatus] ?? []
  // The reason picked last time for this status starts selected.
  useEffect(() => {
    if (!open || reason) return
    // Only a reason this status offers comes back (readLastReason checks it).
    const last = readLastReason(targetStatus)
    if (last) setReason(last)
    // Only when the dialog opens: a cleared choice stays cleared.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, targetStatus])
  // An accepted risk always ends: 90 days ahead unless changed, at most a year.
  const [expiresAt, setExpiresAt] = useState(() => acceptanceDate(defaultDays))
  const [step, setStep] = useState<'input' | 'confirm'>('input')
  const { trigger: requestApproval, isMutating } = useRequestApproval(findingId)
  // The organization's false-positive or risk acceptance level may let a
  // person with approval permission decide alone.
  const isAccepted = targetStatus === 'accepted'
  const decideAlone = (isFalsePositive || isAccepted) && fpPolicy?.can_decide_alone === true
  // Nobody but the caller could approve the request.
  const nobodyElse =
    !decideAlone &&
    !!evaluation &&
    evaluation.tier !== 'single' &&
    evaluation.eligible_approvers === 0
  const othersMayDecideAlone =
    (isFalsePositive || isAccepted) &&
    fpPolicy?.single_person === true &&
    !fpPolicy.can_decide_alone

  const statusConfig = FINDING_STATUS_CONFIG[targetStatus]
  const statusLabel = statusConfig ? t(statusConfig.labelKey, statusConfig.label) : targetStatus
  const showExpiryPicker = targetStatus === 'accepted'
  const minDate = acceptanceDate(1)
  const maxDate = capDays >= 365 ? acceptanceDate(0, 1) : acceptanceDate(capDays)
  const expiryValid =
    !showExpiryPicker || (!!expiresAt && expiresAt >= minDate && expiresAt <= maxDate)
  // The policy's cap may arrive after the dialog opened: keep the end within it.
  useEffect(() => {
    if (showExpiryPicker && expiresAt > maxDate) setExpiresAt(maxDate)
  }, [showExpiryPicker, expiresAt, maxDate])
  const noteLength = justification.trim().length
  const noteTooShort = minNote > 0 && noteLength > 0 && noteLength < minNote
  const noteTooShortText = t(
    'findingApprovals.evaluation.noteTooShort',
    'Write at least {count} characters for this approval.',
    { count: minNote }
  )
  const justificationRequired = t('findings.approvalDialog.noteRequired', 'Write a note')

  const reasonRequired = t('findings.approvalDialog.reasonRequired', 'Choose a reason')

  const handleNext = () => {
    if (!reason) {
      toast.error(reasonRequired)
      return
    }
    if (!noteOptional && !justification.trim()) {
      toast.error(justificationRequired)
      return
    }
    if (noteLength < minNote) {
      toast.error(noteTooShortText)
      return
    }
    if (!expiryValid) {
      toast.error(
        t('findings.approvalDialog.expiryInvalid', 'Choose an expiry date within {days} days', {
          days: capDays,
        })
      )
      return
    }
    setStep('confirm')
  }

  const handleBack = () => {
    setStep('input')
  }

  const handleSubmit = async () => {
    if (!noteOptional && !justification.trim()) {
      toast.error(justificationRequired)
      return
    }

    try {
      const result = await requestApproval({
        requested_status: targetStatus,
        justification: justification.trim(),
        closure_reason: reason,
        ...(showExpiryPicker && expiresAt
          ? { expires_at: new Date(`${expiresAt}T00:00:00`).toISOString() }
          : {}),
      })
      writeLastReason(targetStatus, reason)
      const appliedAlone =
        (result as { status?: string; single_person?: boolean } | undefined)?.single_person === true
      toast.success(
        appliedAlone && isAccepted
          ? t(
              'findingApprovals.single.appliedAccept',
              'Risk accepted until {date}. It is recorded with your name and reason.',
              { date: formatDate(new Date(`${expiresAt}T00:00:00`)) }
            )
          : appliedAlone
            ? t(
                'findingApprovals.single.applied',
                'Marked a false positive. It is recorded with your name and reason.'
              )
            : t('findings.approvalDialog.submitted', 'Approval request submitted for "{status}"', {
                status: statusLabel,
              })
      )
      setJustification('')
      setReason('')
      setExpiresAt(acceptanceDate(defaultDays))
      setStep('input')
      onOpenChange(false)
      await onSuccess?.(result as (ApiApproval & { single_person?: boolean }) | undefined)
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
              {/* The organization's level decides whether this is a request
                  or a decision; the copy says which. */}
              <DialogTitle>
                {decideAlone && isAccepted
                  ? t('findings.approvalDialog.titleDecideAccept', 'Accept the risk')
                  : decideAlone
                    ? t('findings.approvalDialog.titleDecide', 'Mark as false positive')
                    : t('findings.approvalDialog.title', 'Request Status Approval')}
              </DialogTitle>
              <DialogDescription>
                {decideAlone && noteOptional
                  ? t(
                      'findings.approvalDialog.descriptionDecideNoteOptional',
                      'Your organization lets you decide this alone. Choose a reason; a note is optional.'
                    )
                  : decideAlone
                    ? t(
                        'findings.approvalDialog.descriptionDecide',
                        'Your organization lets you decide this alone. Choose a reason and explain it.'
                      )
                    : t(
                        'findings.approvalDialog.descriptionRequest',
                        'Changing the status to {status} needs approval. Give a justification.',
                        { status: statusLabel }
                      )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <div className="grid gap-4 py-4">
                {decideAlone && (
                  <div
                    role="status"
                    className="rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-sm"
                  >
                    {isAccepted
                      ? t(
                          'findingApprovals.single.acceptNotice',
                          "This organization doesn't require approval for this finding: the risk is accepted at once, until the date you choose. The decision is audited, listed in the approvals digest and flagged for review if the finding later becomes more serious."
                        )
                      : t(
                          'findingApprovals.single.notice',
                          "This organization doesn't require approval for this finding: it is marked a false positive at once. The decision is audited and flagged for review if the finding later becomes more serious."
                        )}
                  </div>
                )}
                {evaluation && !decideAlone && evaluation.tier !== 'single' && (
                  <ApprovalEvaluationBanner evaluation={evaluation} />
                )}
                {nobodyElse && (
                  <p className="text-sm" data-testid="approval-dialog-nobody-else">
                    {isOwner()
                      ? t(
                          'findings.approvalDialog.nobodyElseOwner',
                          'Nobody else can approve this. If you are the only member of your organization, you can approve it yourself once it is sent, with a code from your authenticator app.'
                        )
                      : t(
                          'findings.approvalDialog.nobodyElse',
                          'Nobody else can approve this. Ask an owner to give someone the approve permission.'
                        )}
                  </p>
                )}
                {othersMayDecideAlone && (
                  <p className="text-sm text-muted-foreground">
                    {isAccepted
                      ? t(
                          'findingApprovals.single.othersNoticeAccept',
                          'A person with approval permission could accept this risk alone; your request waits for one of them.'
                        )
                      : t(
                          'findingApprovals.single.othersNotice',
                          'A person with approval permission could mark this finding a false positive alone; your request waits for one of them.'
                        )}
                  </p>
                )}
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
                    {noteOptional
                      ? t('findings.approvalDialog.noteOptional', 'Note (optional)')
                      : t('findings.approvalDialog.note', 'Note')}
                  </Label>
                  <Textarea
                    id="justification"
                    placeholder={t(
                      'findings.approvalDialog.notePlaceholder',
                      'What did you check?'
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
                    {minNote > 1 &&
                      `, ${t('findingApprovals.evaluation.noteMin', 'at least {count}', {
                        count: minNote,
                      })}`}
                  </p>
                  {noteTooShort && (
                    <p className="text-xs text-destructive" role="alert">
                      {noteTooShortText}
                    </p>
                  )}
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
                        'The finding reopens on this date. At most {days} days ahead for its priority.',
                        { days: capDays }
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
                disabled={
                  !reason ||
                  (!noteOptional && !justification.trim()) ||
                  noteLength < minNote ||
                  !expiryValid
                }
              >
                {t('findings.approvalDialog.review', 'Review')}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>
                {decideAlone && isAccepted
                  ? t('findings.approvalDialog.confirmTitleDecideAccept', 'Confirm risk acceptance')
                  : decideAlone
                    ? t('findings.approvalDialog.confirmTitleDecide', 'Confirm false positive')
                    : t('findings.approvalDialog.confirmTitle', 'Confirm Approval Request')}
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
                {justification.trim() && (
                  <div>
                    <span className="font-medium text-muted-foreground">
                      {t('common.awaitingApproval.note', 'Note:')}
                    </span>
                    <p className="mt-1 rounded-md border bg-muted/50 p-2 text-sm whitespace-pre-wrap break-words">
                      {justification}
                    </p>
                  </div>
                )}
                {showExpiryPicker && expiresAt && (
                  <div>
                    <span className="font-medium text-muted-foreground">
                      {t('findings.approvalDialog.expires', 'Expires:')}
                    </span>{' '}
                    {formatDate(new Date(`${expiresAt}T00:00:00`))}
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
                  : decideAlone && isAccepted
                    ? t('findingApprovals.single.submitAccept', 'Accept the risk')
                    : decideAlone
                      ? t('findingApprovals.single.submit', 'Mark as false positive')
                      : t('findings.approvalDialog.submit', 'Submit for Approval')}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
