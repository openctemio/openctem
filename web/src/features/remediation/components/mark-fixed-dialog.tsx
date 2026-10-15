'use client'

import { useState, type ReactNode } from 'react'
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
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import type { MarkFixedRequest, MarkFixedResult } from '../api/mark-fixed.types'

// Above this many open findings, require explicit approval (mirrors the backend
// bulk abuse-guard's default size ceiling).
const APPROVAL_THRESHOLD = 500

interface MarkFixedDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: ReactNode
  /** Open findings the action covers (drives the large-bulk confirmation). */
  openCount: number
  submitting: boolean
  onSubmit: (req: MarkFixedRequest) => Promise<MarkFixedResult | undefined>
  onSuccess?: () => void
}

/**
 * The one "mark fixed" dialog for remediation groups and campaigns: a note is
 * required, findings move to fix applied (each one is then verified on its
 * own: retest, covered scan or a reviewer), and every finding that was not
 * updated is listed with the reason.
 */
export function MarkFixedDialog({
  open,
  onOpenChange,
  title,
  description,
  openCount,
  submitting,
  onSubmit,
  onSuccess,
}: MarkFixedDialogProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canClaim = hasPermission(Permission.FindingsFixApply)
  const [resolution, setResolution] = useState('')
  const [approved, setApproved] = useState(false)
  const [result, setResult] = useState<MarkFixedResult | null>(null)
  const needsApproval = openCount > APPROVAL_THRESHOLD

  const close = (next: boolean) => {
    if (!next) {
      setResolution('')
      setApproved(false)
      setResult(null)
    }
    onOpenChange(next)
  }

  const handleSubmit = async () => {
    if (needsApproval && !approved) {
      toast.error(
        t('remediation.markFixed.confirmRequired', 'Confirm this large change to proceed')
      )
      return
    }
    try {
      const res = await onSubmit({ resolution: resolution.trim(), approved: approved || undefined })
      const updated = res?.updated ?? 0
      toast.success(
        t('remediation.markFixed.done', '{count} findings marked fixed', { count: updated })
      )
      onSuccess?.()
      if (res && res.rows.length > 0) {
        // Keep the dialog open on the outcome: no failure is silent.
        setResult(res)
        return
      }
      close(false)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('remediation.markFixed.error', 'Could not mark the findings fixed'))
      )
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <DialogBody>
          {result ? (
            <div className="space-y-3" data-testid="mark-fixed-result">
              <p className="text-sm">
                {t(
                  'remediation.markFixed.summary',
                  '{updated} marked fixed, {skipped} skipped, {failed} not changed, {queued} re-checks queued.',
                  {
                    updated: result.updated,
                    skipped: result.skipped,
                    failed: result.failed,
                    queued: result.validations_queued,
                  }
                )}
              </p>
              <ul className="max-h-64 space-y-1 overflow-y-auto text-xs">
                {result.rows.map((r) => (
                  <li key={r.finding_id} className="break-words">
                    <span className="font-mono">{r.finding_id.slice(0, 8)}</span>{' '}
                    <span className="text-muted-foreground">
                      {r.outcome === 'skipped'
                        ? t('remediation.markFixed.outcomeSkipped', 'skipped')
                        : t('remediation.markFixed.outcomeFailed', 'not changed')}
                      : {r.reason}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-muted-foreground text-xs">
                {t(
                  'remediation.markFixed.explain',
                  'Each finding moves to fix applied. A retest, a covered scan or a reviewer then verifies it and closes it; nothing is closed for the whole group.'
                )}
              </p>
              <div className="space-y-2">
                <Label htmlFor="mark-fixed-note">
                  {t('findings.statusNote.label', 'Note (required)')}
                </Label>
                <Textarea
                  id="mark-fixed-note"
                  placeholder={t(
                    'remediation.markFixed.notePlaceholder',
                    'e.g. Patched via change CR-1234'
                  )}
                  value={resolution}
                  onChange={(e) => setResolution(e.target.value)}
                  rows={3}
                />
              </div>
              {needsApproval ? (
                <div className="flex items-start gap-2">
                  <Checkbox
                    id="mark-fixed-approve"
                    checked={approved}
                    onCheckedChange={(c) => setApproved(c === true)}
                  />
                  <Label htmlFor="mark-fixed-approve" className="text-sm font-normal leading-snug">
                    {t(
                      'remediation.markFixed.confirmLarge',
                      'I confirm marking {count} findings fixed at once.',
                      { count: openCount }
                    )}
                  </Label>
                </div>
              ) : null}
              {!canClaim ? (
                <p className="text-destructive text-xs">
                  {t(
                    'remediation.markFixed.noPermission',
                    'You need the permission to mark findings fixed.'
                  )}
                </p>
              ) : null}
            </div>
          )}
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => close(false)} disabled={submitting}>
            {result ? t('remediation.markFixed.close', 'Close') : t('common.cancel', 'Cancel')}
          </Button>
          {result ? null : (
            <Button onClick={handleSubmit} disabled={submitting || !canClaim || !resolution.trim()}>
              {submitting ? <Loader2 className="me-2 h-4 w-4 animate-spin" /> : null}
              {t('remediation.markFixed.submit', 'Mark fixed')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
