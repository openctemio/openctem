'use client'

/**
 * The bulk "Dismiss" dialog of the findings list
 * (server/docs/architecture/findings-bulk-by-filter.md, "Bulk dismiss"): one
 * decision (false positive, or accept the risk until a date), one reason, one
 * note, and a live server preview of how the selection splits before anything
 * changes. The server decides every finding with the same policy as a single
 * request; the dialog only reads its answer.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { ChevronRight, Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { DialogSubmitError } from '@/components/ui/dialog-submit-error'
import { Button } from '@/components/ui/button'
import { ChoiceGroup } from '@/components/ui/choice-group'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { SeverityBadge } from '@/components/ui/severity-badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatNumber } from '@/lib/app-locale'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { PERSON_CLOSURE_REASONS, closureReasonLabel } from '../lib/closure'
import {
  BULK_DISMISS_MAX,
  applyBulkDismiss,
  dismissBody,
  dismissNoteMinLength,
  errorCode,
  errorCount,
  idempotencyKeyFor,
  previewBulkDismiss,
  previewLines,
  previewReason,
  readLastReason,
  writeLastReason,
  type DismissResult,
  type DismissSelection,
  type DismissStatus,
  type PreviewLine,
} from '../lib/bulk-dismiss'

/** How long typing settles before the preview asks the server again. */
const PREVIEW_DEBOUNCE_MS = 300
/** An accepted risk ends 90 days ahead unless changed, at most a year. */
const DEFAULT_ACCEPT_DAYS = 90

/** Local calendar date (YYYY-MM-DD) `days` days and `years` years from today. */
function calendarDate(days: number, years = 0): string {
  const d = new Date()
  d.setFullYear(d.getFullYear() + years)
  d.setDate(d.getDate() + days)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

/**
 * Where a digit is typed text, not a reason shortcut. The reason picker (a
 * combobox trigger that takes no typed digits) is where the dialog opens.
 */
const TYPING_SELECTOR = 'input, textarea, select, [contenteditable="true"]'

type PreviewState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ready'; key: string; data: DismissResult }
  | { kind: 'failed'; message: string }

export interface SuggestedRule {
  tool_name?: string
  rule_id?: string
  suppression_type?: 'false_positive' | 'accepted_risk'
}

export interface BulkDismissDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The selection when the dialog opened: checked rows, or the list's filter and its count. */
  selection: DismissSelection | null
  /** Called with the server's answer once the Dismiss is applied (the toast and Undo are the caller's). */
  onApplied: (result: DismissResult) => void
  /**
   * Opens the suppression rule form, with the shared tool rule when there is
   * one. Omitted when the user cannot create rules.
   */
  onCreateRule?: (defaults?: SuggestedRule) => void
}

export function BulkDismissDialog({
  open,
  onOpenChange,
  selection,
  onApplied,
  onCreateRule,
}: BulkDismissDialogProps) {
  const { t } = useTranslation()
  const [status, setStatus] = useState<DismissStatus>('false_positive')
  const [reason, setReason] = useState('')
  const [note, setNote] = useState('')
  const [endDate, setEndDate] = useState(() => calendarDate(DEFAULT_ACCEPT_DAYS))
  const [preview, setPreview] = useState<PreviewState>({ kind: 'idle' })
  // A filter selection's count as last confirmed; a changed list asks again.
  const [confirmedTotal, setConfirmedTotal] = useState<number | null>(null)
  const [changedTo, setChangedTo] = useState<number | null>(null)
  const [tooLarge, setTooLarge] = useState<number | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<{ message: string; requestId?: string } | null>(
    null
  )
  // One idempotency key per dialog open, kept across retries of one request.
  const keyRef = useRef<{ key: string; body: string } | null>(null)
  // The dialog opens on the reason, so 1-7 work at once.
  const reasonRef = useRef<HTMLButtonElement>(null)

  const reasons = useMemo(() => PERSON_CLOSURE_REASONS[status] ?? [], [status])

  // A fresh form each time the dialog opens; the last reason is preselected.
  useEffect(() => {
    if (!open) return
    setStatus('false_positive')
    setReason(readLastReason('false_positive'))
    setNote('')
    setEndDate(calendarDate(DEFAULT_ACCEPT_DAYS))
    setPreview({ kind: 'idle' })
    setConfirmedTotal(null)
    setChangedTo(null)
    setTooLarge(null)
    setSubmitError(null)
    keyRef.current = null
  }, [open])

  const changeStatus = (next: DismissStatus) => {
    setStatus(next)
    setReason(readLastReason(next))
    setSubmitError(null)
  }

  // The selection as sent: a filter carries the count the user confirmed.
  const effective = useMemo<DismissSelection | null>(() => {
    if (!selection) return null
    if (selection.kind === 'filter' && confirmedTotal !== null) {
      return { ...selection, total: confirmedTotal }
    }
    return selection
  }, [selection, confirmedTotal])
  const total = effective ? (effective.kind === 'ids' ? effective.ids.length : effective.total) : 0
  const overCap = tooLarge ?? (total > BULK_DISMISS_MAX ? total : null)

  const minDate = calendarDate(1)
  const maxDate = calendarDate(0, 1)
  const endValid = status !== 'accepted' || (!!endDate && endDate >= minDate && endDate <= maxDate)
  const expiresAt =
    status === 'accepted' && endValid ? new Date(`${endDate}T00:00:00`).toISOString() : undefined

  // The preview does not depend on the reason or the note: it asks again
  // only when the selection, the status or the end date changes.
  const previewBodyText = useMemo(() => {
    if (!effective || overCap !== null || changedTo !== null || !endValid) return ''
    return JSON.stringify(
      dismissBody(effective, {
        status,
        closureReason: previewReason(status, ''),
        note: '',
        expiresAt,
      })
    )
  }, [effective, overCap, changedTo, endValid, status, expiresAt])

  useEffect(() => {
    if (!open || !previewBodyText) return
    let live = true
    setPreview({ kind: 'loading' })
    const timer = setTimeout(() => {
      previewBulkDismiss(JSON.parse(previewBodyText) as Record<string, unknown>)
        .then((data) => live && setPreview({ kind: 'ready', key: previewBodyText, data }))
        .catch((error: unknown) => {
          if (!live) return
          const code = errorCode(error)
          if (code === 'BULK_DISMISS_TOO_LARGE') {
            setTooLarge(errorCount(error) ?? total)
            setPreview({ kind: 'idle' })
          } else if (code === 'SELECTION_CHANGED' && errorCount(error) !== null) {
            setChangedTo(errorCount(error))
            setPreview({ kind: 'idle' })
          } else {
            setPreview({
              kind: 'failed',
              message: getErrorMessage(
                error,
                t('findings.bulkDismiss.previewFailed', 'Could not check the findings first.')
              ),
            })
          }
        })
    }, PREVIEW_DEBOUNCE_MS)
    return () => {
      live = false
      clearTimeout(timer)
    }
    // total and t only shape the error text.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, previewBodyText])

  const ready =
    preview.kind === 'ready' && preview.key === previewBodyText ? preview.data : undefined
  const minNote = dismissNoteMinLength(preview.kind === 'failed' ? null : ready)
  const noteLength = note.trim().length
  const noteMissing = noteLength < minNote
  const actionable = ready ? ready.counts.decided + ready.counts.grouped : 0
  const canSubmit =
    !!effective &&
    overCap === null &&
    changedTo === null &&
    !!reason &&
    !noteMissing &&
    endValid &&
    !submitting &&
    (preview.kind === 'failed' || actionable > 0)

  const submit = useCallback(async () => {
    if (!canSubmit || !effective) return
    const body = dismissBody(effective, { status, closureReason: reason, note, expiresAt })
    keyRef.current = idempotencyKeyFor(keyRef.current, body)
    setSubmitting(true)
    setSubmitError(null)
    try {
      const result = await applyBulkDismiss(body, keyRef.current.key)
      writeLastReason(status, reason)
      onOpenChange(false)
      onApplied(result)
    } catch (error) {
      const code = errorCode(error)
      if (code === 'SELECTION_CHANGED' && errorCount(error) !== null) {
        setChangedTo(errorCount(error))
      } else if (code === 'BULK_DISMISS_TOO_LARGE') {
        setTooLarge(errorCount(error) ?? total)
      } else {
        const message =
          code === 'STEP_UP_REQUIRED'
            ? t(
                'findings.bulkDismiss.stepUpCanceled',
                'Sign in again to dismiss this many at once. Nothing was changed.'
              )
            : getErrorMessage(
                error,
                t('findings.bulkDismiss.failed', 'Could not dismiss the findings')
              )
        setSubmitError({
          message,
          requestId: (error as { requestId?: string } | null)?.requestId,
        })
      }
    } finally {
      setSubmitting(false)
    }
  }, [canSubmit, effective, status, reason, note, expiresAt, onOpenChange, onApplied, total, t])

  // 1-7 pick a reason; Ctrl/Cmd+Enter dismisses. Esc is the dialog's own.
  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault()
      void submit()
      return
    }
    if (e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return
    const n = Number(e.key)
    if (!Number.isInteger(n) || n < 1 || n > reasons.length) return
    if ((e.target as HTMLElement).closest(TYPING_SELECTOR)) return
    e.preventDefault()
    setReason(reasons[n - 1])
  }

  const confirmChanged = () => {
    if (changedTo === null) return
    setConfirmedTotal(changedTo)
    setChangedTo(null)
  }

  const statusOptions = [
    {
      value: 'false_positive' as const,
      label: t('findings.bulkDismiss.status.falsePositive', 'False positive'),
      hint: t('findings.bulkDismiss.status.falsePositiveHint', 'Not a real problem.'),
    },
    {
      value: 'accepted' as const,
      label: t('findings.bulkDismiss.status.accepted', 'Accept the risk'),
      hint: t(
        'findings.bulkDismiss.status.acceptedHint',
        'Real, but you live with it until a date; then it reopens.'
      ),
    },
  ]

  const sameRule = ready?.same_rule?.suggest ? ready.same_rule : undefined

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="md"
        onKeyDown={onKeyDown}
        onOpenAutoFocus={(e) => {
          if (!reasonRef.current) return
          e.preventDefault()
          reasonRef.current.focus()
        }}
        data-testid="bulk-dismiss-dialog"
      >
        <DialogHeader>
          <DialogTitle>
            {t(
              'findings.bulkDismiss.title',
              '{count, plural, one {Dismiss # finding} other {Dismiss # findings}}',
              { count: total }
            )}
          </DialogTitle>
          <DialogDescription>
            {t(
              'findings.bulkDismiss.description',
              'Each finding follows your organization’s approval rules: the ones you may decide alone change now, the others go to approval as one request.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          {overCap !== null ? (
            <TooLarge count={overCap} onCreateRule={onCreateRule} />
          ) : (
            <div className="grid gap-4 py-1">
              <div className="grid gap-2">
                <Label>{t('findings.bulkDismiss.statusLabel', 'Mark them as')}</Label>
                <ChoiceGroup
                  label={t('findings.bulkDismiss.statusLabel', 'Mark them as')}
                  value={status}
                  options={statusOptions}
                  onValueChange={changeStatus}
                  data-testid="bulk-dismiss-status"
                />
              </div>
              {status === 'accepted' && (
                <div className="grid gap-2">
                  <Label htmlFor="bulk-dismiss-end">
                    {t('findings.bulkDismiss.endLabel', 'Reopens on')}
                  </Label>
                  <Input
                    id="bulk-dismiss-end"
                    type="date"
                    required
                    value={endDate}
                    min={minDate}
                    max={maxDate}
                    onChange={(e) => setEndDate(e.target.value)}
                  />
                  {!endValid && (
                    <p className="text-cap text-destructive" role="alert">
                      {t(
                        'findings.bulkDismiss.endInvalid',
                        'Choose a date from tomorrow to one year ahead.'
                      )}
                    </p>
                  )}
                </div>
              )}
              <div className="grid gap-2">
                <Label htmlFor="bulk-dismiss-reason">
                  {t('findings.bulkDismiss.reasonLabel', 'Reason')}
                </Label>
                <Select value={reason} onValueChange={setReason}>
                  <SelectTrigger
                    ref={reasonRef}
                    id="bulk-dismiss-reason"
                    data-testid="bulk-dismiss-reason"
                  >
                    <SelectValue
                      placeholder={t('findings.bulkDismiss.reasonPlaceholder', 'Choose a reason')}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {reasons.map((r, i) => (
                      <SelectItem key={r} value={r}>
                        <span className="flex w-full items-center gap-3">
                          <span className="min-w-0 flex-1">{closureReasonLabel(t, r)}</span>
                          <kbd className="font-mono text-cap text-muted-foreground" aria-hidden>
                            {i + 1}
                          </kbd>
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="bulk-dismiss-note">
                  {minNote > 0
                    ? t('findings.bulkDismiss.noteLabel', 'Note')
                    : t('findings.bulkDismiss.noteOptional', 'Note (optional)')}
                </Label>
                <Textarea
                  id="bulk-dismiss-note"
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder={t('findings.bulkDismiss.notePlaceholder', 'What did you check?')}
                  rows={3}
                  maxLength={2000}
                  aria-describedby="bulk-dismiss-note-hint"
                />
                <p id="bulk-dismiss-note-hint" className="text-cap text-muted-foreground">
                  {minNote > 1
                    ? t(
                        'findings.bulkDismiss.noteHintMin',
                        'The approver reads it. Write at least {count, plural, one {# character} other {# characters}}.',
                        { count: minNote }
                      )
                    : minNote === 1
                      ? t('findings.bulkDismiss.noteHint', 'The approver reads it.')
                      : t(
                          'findings.bulkDismiss.noteHintOptional',
                          'You decide these alone and none is serious, so the reason is enough.'
                        )}
                </p>
              </div>
              <PreviewPanel
                preview={preview}
                ready={ready}
                changedTo={changedTo}
                onConfirmChanged={confirmChanged}
              />
              {ready?.step_up_required && (
                <p className="text-body text-muted-foreground" data-testid="bulk-dismiss-stepup">
                  {t(
                    'findings.bulkDismiss.stepUp',
                    'You will be asked to sign in again before so many are dismissed at once.'
                  )}
                </p>
              )}
              {sameRule && (
                <div
                  className="grid gap-2 rounded-md border px-3 py-2"
                  data-testid="bulk-dismiss-rule-hint"
                >
                  <p className="text-body">
                    {t(
                      'findings.bulkDismiss.ruleHint',
                      '{count} of these come from one rule ({rule}). A suppression rule fits a repeating pattern better: it also covers new findings from that rule, and it ends in 90 days unless renewed.',
                      {
                        count: sameRule.count,
                        rule: toDisplayText(
                          sameRule.tool
                            ? `${sameRule.tool}: ${sameRule.rule_id}`
                            : sameRule.rule_id,
                          80
                        ),
                      }
                    )}
                  </p>
                  {onCreateRule && (
                    <div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          onOpenChange(false)
                          onCreateRule({
                            tool_name: sameRule.tool,
                            rule_id: sameRule.rule_id,
                            suppression_type:
                              status === 'accepted' ? 'accepted_risk' : 'false_positive',
                          })
                        }}
                      >
                        {t('findings.bulkDismiss.createRule', 'Create a rule instead')}
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </DialogBody>
        <DialogSubmitError message={submitError?.message} requestId={submitError?.requestId} />
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          {overCap === null && (
            <Button
              onClick={() => void submit()}
              disabled={!canSubmit}
              aria-keyshortcuts="Control+Enter Meta+Enter"
              data-testid="bulk-dismiss-submit"
            >
              {submitting && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
              {ready && actionable > 0
                ? t('findings.bulkDismiss.submitCount', 'Dismiss {count}', {
                    count: formatNumber(actionable),
                  })
                : t('findings.bulkDismiss.submit', 'Dismiss')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** A selection above 500: the count, and a suppression rule instead. */
function TooLarge({
  count,
  onCreateRule,
}: {
  count: number
  onCreateRule?: (defaults?: SuggestedRule) => void
}) {
  const { t } = useTranslation()
  return (
    <div className="grid gap-3 py-1" data-testid="bulk-dismiss-too-large">
      <p className="text-body">
        {t(
          'findings.bulkDismiss.tooLarge',
          '{count, plural, one {# finding matches} other {# findings match}}. Dismiss takes at most {max} at a time. Narrow the filter, or create a suppression rule: it covers every matching finding, now and later, and ends on a date.',
          { count, max: BULK_DISMISS_MAX }
        )}
      </p>
      {onCreateRule && (
        <div>
          <Button variant="outline" size="sm" onClick={() => onCreateRule()}>
            {t('findings.bulkDismiss.createRuleOnly', 'Create a suppression rule')}
          </Button>
        </div>
      )}
    </div>
  )
}

/** The live preview: what will happen, in plain words, each part expandable. */
function PreviewPanel({
  preview,
  ready,
  changedTo,
  onConfirmChanged,
}: {
  preview: PreviewState
  ready: DismissResult | undefined
  changedTo: number | null
  onConfirmChanged: () => void
}) {
  const { t } = useTranslation()
  const lines = ready ? previewLines(t, ready) : []
  return (
    <section
      className="grid gap-1 rounded-md bg-muted/60 px-3 py-2.5"
      aria-live="polite"
      aria-label={t('findings.bulkDismiss.previewLabel', 'What will happen')}
      data-testid="bulk-dismiss-preview"
    >
      <h3 className="text-cap-m text-muted-foreground">
        {t('findings.bulkDismiss.previewLabel', 'What will happen')}
      </h3>
      {changedTo !== null ? (
        <div className="grid gap-2">
          <p className="text-body">
            {t(
              'findings.bulkDismiss.changed',
              'The list changed: {count, plural, one {# finding matches} other {# findings match}} now.',
              { count: changedTo }
            )}
          </p>
          <div>
            <Button variant="outline" size="sm" onClick={onConfirmChanged}>
              {t('findings.bulkDismiss.useNewCount', 'Check the {count} again', {
                count: formatNumber(changedTo),
              })}
            </Button>
          </div>
        </div>
      ) : preview.kind === 'failed' ? (
        <p className="text-body text-muted-foreground">
          {preview.message}{' '}
          {t(
            'findings.bulkDismiss.previewFailedHint',
            'You can still dismiss: the server checks every finding and lists any it skips.'
          )}
        </p>
      ) : !ready ? (
        <p className="flex items-center gap-2 text-body text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          {t('findings.bulkDismiss.previewLoading', 'Checking each finding…')}
        </p>
      ) : lines.length === 0 ? (
        <p className="text-body text-muted-foreground">
          {t('findings.bulkDismiss.previewNothing', 'None of these can be dismissed.')}
        </p>
      ) : (
        <ul className="grid gap-0.5">
          {lines.map((line) => (
            <PreviewRow key={line.kind} line={line} />
          ))}
        </ul>
      )}
    </section>
  )
}

function PreviewRow({ line }: { line: PreviewLine }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const more = line.count - line.items.length
  if (line.items.length === 0) {
    return (
      <li className="py-1 text-body" data-testid={`bulk-dismiss-line-${line.kind}`}>
        {line.text}
      </li>
    )
  }
  return (
    <li data-testid={`bulk-dismiss-line-${line.kind}`}>
      <Collapsible open={open} onOpenChange={setOpen}>
        <CollapsibleTrigger className="-mx-1 flex w-full items-start gap-1.5 rounded px-1 py-1 text-start text-body hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          <ChevronRight
            className={cn(
              'mt-0.5 h-4 w-4 shrink-0 text-muted-foreground transition-transform motion-reduce:transition-none',
              open && 'rotate-90'
            )}
            aria-hidden
          />
          <span className="min-w-0">{line.text}</span>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <ul className="grid gap-1 py-1 ps-6" data-testid={`bulk-dismiss-items-${line.kind}`}>
            {line.items.map((item) => (
              <li key={item.id} className="flex min-w-0 items-center gap-2 text-dense">
                {item.severity && <SeverityBadge severity={item.severity} className="shrink-0" />}
                <span className="min-w-0 truncate" title={toDisplayText(item.title ?? '', 300)}>
                  {item.title
                    ? toDisplayText(item.title, 120)
                    : t('findings.bulkDismiss.untitled', 'A finding you cannot see')}
                </span>
              </li>
            ))}
            {more > 0 && (
              <li className="text-cap text-muted-foreground">
                {t('findings.bulkDismiss.more', 'and {count} more', {
                  count: formatNumber(more),
                })}
              </li>
            )}
          </ul>
        </CollapsibleContent>
      </Collapsible>
    </li>
  )
}
