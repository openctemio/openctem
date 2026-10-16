'use client'

/**
 * Ask for one exception (accepted risk or false positive) over every open
 * finding of a remediation task, decided once by the approvers
 * (api/docs/rfcs/RFC-111-approval-policy.md). A live preview shows the group
 * tier and why, who may decide, and each finding with its own tier and end.
 * Informational only: the API evaluates again when the request is made.
 */

import { useEffect, useRef, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { Skeleton } from '@/components/ui/skeleton'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import {
  approvalBatchApi,
  type ApprovalBatch,
  type GroupExceptionInput,
  type GroupExceptionPreview,
  type GroupExceptionPreviewMember,
  type GroupExceptionStatus,
} from '../api/use-approval-batches'
import { groupSkipText, tierLabel } from '../lib/approval-policy'
import { PERSON_CLOSURE_REASONS, closureReasonLabel } from '../lib/closure'
import { ApprovalEvaluationBanner } from './approval-evaluation-banner'

/** Days an accepted risk lasts unless the requester picks another date. */
const DEFAULT_ACCEPTANCE_DAYS = 90
/** Wait after the last change before asking for a preview. */
const PREVIEW_DEBOUNCE_MS = 400
const NOTE_MAX = 2000

/** Local calendar date (YYYY-MM-DD) `days` days and `years` years from today. */
function localDate(days: number, years = 0): string {
  const d = new Date()
  d.setFullYear(d.getFullYear() + years)
  d.setDate(d.getDate() + days)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

function isPendingConflict(err: unknown): boolean {
  return err instanceof ApiClientError && err.statusCode === 409
}

interface GroupExceptionDialogProps {
  taskId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The exception was requested. */
  onCreated?: (batch: ApprovalBatch) => void | Promise<void>
  /** The task already has a pending exception (409): refresh what shows it. */
  onPendingConflict?: () => void | Promise<void>
}

export function GroupExceptionDialog({
  taskId,
  open,
  onOpenChange,
  onCreated,
  onPendingConflict,
}: GroupExceptionDialogProps) {
  const { t } = useTranslation()
  const [status, setStatus] = useState<GroupExceptionStatus>('accepted')
  const [reason, setReason] = useState('')
  const [note, setNote] = useState('')
  const [expiresAt, setExpiresAt] = useState(() => localDate(DEFAULT_ACCEPTANCE_DAYS))
  const [preview, setPreview] = useState<GroupExceptionPreview | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  // Only the newest preview answer counts.
  const seq = useRef(0)

  const accepted = status === 'accepted'
  const minDate = localDate(1)
  const maxDate = localDate(0, 1)
  const expiryValid = !accepted || (!!expiresAt && expiresAt >= minDate && expiresAt <= maxDate)
  const expiresIso = accepted && expiresAt ? new Date(`${expiresAt}T00:00:00`).toISOString() : ''

  const pendingText = t(
    'findingApprovals.group.pendingConflict',
    'This task already has a pending exception. Decide or cancel it first.'
  )

  useEffect(() => {
    if (!open || !reason || !expiryValid) {
      seq.current++
      setPreview(null)
      setPreviewError(null)
      setPreviewing(false)
      return
    }
    const mine = ++seq.current
    setPreviewing(true)
    const timer = setTimeout(() => {
      const body: GroupExceptionInput = {
        requested_status: status,
        closure_reason: reason,
        justification: '',
        ...(expiresIso ? { expires_at: expiresIso } : {}),
      }
      approvalBatchApi.preview(taskId, body).then(
        (res) => {
          if (seq.current !== mine) return
          setPreview(res)
          setPreviewError(null)
          setPreviewing(false)
        },
        (err: unknown) => {
          if (seq.current !== mine) return
          setPreview(null)
          setPreviewing(false)
          if (isPendingConflict(err)) {
            setPreviewError(pendingText)
            void onPendingConflict?.()
          } else {
            setPreviewError(
              getErrorMessage(
                err,
                t('findingApprovals.group.previewFailed', 'Could not preview this exception.')
              )
            )
          }
        }
      )
    }, PREVIEW_DEBOUNCE_MS)
    return () => clearTimeout(timer)
    // pendingText and onPendingConflict are stable enough; re-running on them
    // would re-request the preview on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, taskId, status, reason, expiresIso, expiryValid])

  const evaluation = preview?.evaluation
  const minNote = Math.max(1, evaluation?.min_note_length ?? 1)
  const noteLength = note.trim().length
  const noteTooShort = noteLength > 0 && noteLength < minNote
  const included = preview?.included ?? 0
  const canSubmit =
    !!reason &&
    expiryValid &&
    noteLength >= minNote &&
    !!preview &&
    included > 0 &&
    !previewing &&
    !submitting

  const reset = () => {
    setStatus('accepted')
    setReason('')
    setNote('')
    setExpiresAt(localDate(DEFAULT_ACCEPTANCE_DAYS))
  }

  const changeStatus = (value: string) => {
    setStatus(value as GroupExceptionStatus)
    // The reason codes differ per status.
    setReason('')
  }

  const submit = async () => {
    if (!canSubmit) return
    setSubmitting(true)
    try {
      const batch = await approvalBatchApi.request(taskId, {
        requested_status: status,
        closure_reason: reason,
        justification: note.trim(),
        ...(expiresIso ? { expires_at: expiresIso } : {}),
      })
      toast.success(t('findingApprovals.group.requested', 'Exception requested'), {
        description: t(
          'findingApprovals.group.requestedDesc',
          '{count} finding(s) wait for one decision ({tier}).',
          { count: batch.member_count, tier: tierLabel(t, batch.tier) }
        ),
      })
      reset()
      onOpenChange(false)
      await onCreated?.(batch)
    } catch (err) {
      if (isPendingConflict(err)) {
        toast.error(pendingText)
        onOpenChange(false)
        await onPendingConflict?.()
      } else {
        toast.error(
          getErrorMessage(
            err,
            t('findingApprovals.group.requestFailed', 'Could not request the exception.')
          )
        )
      }
    } finally {
      setSubmitting(false)
    }
  }

  const reasons = PERSON_CLOSURE_REASONS[status] ?? []

  return (
    <Dialog open={open} onOpenChange={(v) => !submitting && onOpenChange(v)}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('findingApprovals.group.title', 'Request an exception')}</DialogTitle>
          <DialogDescription>
            {t(
              'findingApprovals.group.description',
              'One decision for every open finding of this task. Findings that join the task later are not covered.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label>{t('findingApprovals.group.statusLabel', 'Exception')}</Label>
              <RadioGroup
                value={status}
                onValueChange={changeStatus}
                className="grid gap-2 sm:grid-cols-2"
                aria-label={t('findingApprovals.group.statusLabel', 'Exception')}
              >
                {(['accepted', 'false_positive'] as const).map((s) => (
                  <Label
                    key={s}
                    htmlFor={`group-exception-${s}`}
                    className="flex cursor-pointer items-center gap-2 rounded-md border p-3 font-normal has-[[data-state=checked]]:border-primary"
                  >
                    <RadioGroupItem id={`group-exception-${s}`} value={s} />
                    {s === 'accepted'
                      ? t('findingApprovals.kind.accepted', 'Accepted risk')
                      : t('findingApprovals.kind.false_positive', 'False positive')}
                  </Label>
                ))}
              </RadioGroup>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="group-exception-reason">
                  {t('findings.approvalDialog.reason', 'Reason')}
                </Label>
                <Select value={reason} onValueChange={setReason}>
                  <SelectTrigger id="group-exception-reason">
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
              {accepted && (
                <div className="grid gap-2">
                  <Label htmlFor="group-exception-end">
                    {t('findings.approvalDialog.expiry', 'Acceptance expires on')}
                  </Label>
                  <Input
                    id="group-exception-end"
                    type="date"
                    required
                    value={expiresAt}
                    min={minDate}
                    max={maxDate}
                    onChange={(e) => setExpiresAt(e.target.value)}
                    aria-invalid={!expiryValid}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'findingApprovals.group.endHint',
                      'Within a year. A finding whose own limit is shorter ends earlier.'
                    )}
                  </p>
                </div>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="group-exception-note">
                {t('findings.approvalDialog.justification', 'Justification')}
              </Label>
              <Textarea
                id="group-exception-note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={3}
                maxLength={NOTE_MAX}
                placeholder={t(
                  'findingApprovals.group.notePlaceholder',
                  'Why these findings can wait or are not a risk, and what covers them meanwhile.'
                )}
              />
              <p className="text-xs text-muted-foreground">
                {t('findings.approvalDialog.characters', '{count}/2000 characters', {
                  count: note.length,
                })}
                {` · ${t('findingApprovals.evaluation.noteMin', 'at least {count}', {
                  count: minNote,
                })}`}
              </p>
              {noteTooShort && (
                <p className="text-xs text-destructive" role="alert">
                  {t(
                    'findingApprovals.evaluation.noteTooShort',
                    'Write at least {count} characters for this approval.',
                    { count: minNote }
                  )}
                </p>
              )}
            </div>

            <section
              aria-label={t('findingApprovals.group.previewLabel', 'Who decides')}
              aria-busy={previewing}
              className="grid gap-3"
            >
              {!reason ? (
                <p className="text-sm text-muted-foreground">
                  {t(
                    'findingApprovals.group.previewHint',
                    'Choose a reason to see who decides and which findings are covered.'
                  )}
                </p>
              ) : previewError ? (
                <p
                  role="alert"
                  className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  {previewError}
                </p>
              ) : !preview ? (
                <Skeleton className="h-24 w-full" />
              ) : (
                <>
                  <ApprovalEvaluationBanner evaluation={preview.evaluation} group />
                  <p className="text-sm">
                    {t(
                      'findingApprovals.group.coverage',
                      '{included} finding(s) covered, {skipped} left out.',
                      { included: preview.included, skipped: preview.skipped }
                    )}
                  </p>
                  <GroupExceptionMemberList members={preview.members} accepted={accepted} />
                </>
              )}
            </section>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            {t('findings.approvalDialog.cancel', 'Cancel')}
          </Button>
          <Button onClick={() => void submit()} disabled={!canSubmit}>
            {submitting && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
            {t('findingApprovals.group.submit', 'Request exception')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The preview's findings: each with its tier and end, or why it is left out. */
export function GroupExceptionMemberList({
  members,
  accepted,
}: {
  members: GroupExceptionPreviewMember[]
  accepted: boolean
}) {
  const { t } = useTranslation()
  if (members.length === 0) return null
  return (
    <ul
      className="divide-y rounded-md border text-sm"
      aria-label={t('findingApprovals.group.membersLabel', 'Findings')}
      data-testid="group-exception-members"
    >
      {members.map((m) => (
        <li
          key={m.finding_id}
          className={cn(
            'flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2',
            m.skipped && 'opacity-70'
          )}
          data-testid="group-exception-member"
        >
          <Link
            href={`/findings/${encodeURIComponent(m.finding_id)}`}
            className="min-w-0 flex-1 basis-48 truncate hover:underline"
            title={m.title}
          >
            {m.title || m.finding_id}
          </Link>
          {m.severity && <SeverityBadge severity={m.severity as Severity} />}
          {m.skipped ? (
            <Badge variant="outline" className="text-xs text-muted-foreground">
              {groupSkipText(t, m.skipped)}
            </Badge>
          ) : (
            <>
              {m.tier && (
                <Badge variant="outline" className="text-xs">
                  {tierLabel(t, m.tier)}
                </Badge>
              )}
              {accepted && m.end && (
                <span className="text-xs text-muted-foreground whitespace-nowrap">
                  {t('findingApprovals.group.endsOn', 'ends {date}', {
                    date: new Date(m.end).toLocaleDateString(),
                  })}
                </span>
              )}
              {m.shortened && (
                <Badge
                  variant="outline"
                  className="border-warning/40 text-xs text-warning"
                  title={t(
                    'findingApprovals.group.shortenedHelp',
                    "The date you chose is past this finding's limit, so it ends at its limit."
                  )}
                >
                  {t('findingApprovals.group.shortened', 'Shortened to its limit')}
                </Badge>
              )}
            </>
          )}
        </li>
      ))}
    </ul>
  )
}
