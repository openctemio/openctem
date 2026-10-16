'use client'

/**
 * The sole member of an organization approves their own finding request
 * (api/docs/architecture/finding-status-lifecycle.md, "Sole member"). The
 * API decides whether it is allowed (`self_approval_available` on the list);
 * the dialog asks for a reason and a fresh code from the authenticator app.
 * It is audited, announced on the organization's channels and emailed to the
 * backup contact.
 */

import { useId, useState } from 'react'
import { AlertTriangle, Loader2, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { selfApproveFindingApproval } from '../api/use-findings-api'
import type { ApiApproval } from '../types/finding.types'

const MAX_REASON = 2000

type Translate = ReturnType<typeof useTranslation>['t']

/** The message for a refusal code of POST /approvals/{id}/self-approve. */
export function selfApproveErrorMessage(t: Translate, err: unknown): string {
  const e = err as { code?: unknown; message?: unknown } | null | undefined
  switch (typeof e?.code === 'string' ? e.code : '') {
    case 'SELF_APPROVAL_NOT_ALLOWED':
      return t(
        'findingApprovals.selfApprove.error.notAllowed',
        'You can approve your own request only as the owner of an organization with no other active member.'
      )
    case 'SELF_APPROVAL_NEEDS_TOTP':
      return t(
        'findingApprovals.selfApprove.error.needsTotp',
        'Turn on two-factor authentication first: approving your own request needs a code from your authenticator app.'
      )
    case 'SELF_APPROVAL_INVALID_CODE':
      return t(
        'findingApprovals.selfApprove.error.badCode',
        'The code is wrong or was already used. Wait for a new code and try again.'
      )
    case 'SELF_APPROVAL_REASON_REQUIRED':
      return t('findingApprovals.selfApprove.error.reason', 'Give a reason.')
  }
  if (e && typeof e.message === 'string' && e.message) return e.message
  return t('findingApprovals.selfApprove.error.generic', 'Could not approve the request.')
}

interface FindingSelfApproveDialogProps {
  approval: ApiApproval | null
  onOpenChange: (open: boolean) => void
  onApproved?: () => void
}

export function FindingSelfApproveDialog({
  approval,
  onOpenChange,
  onApproved,
}: FindingSelfApproveDialogProps) {
  const { t } = useTranslation()
  const formId = useId()
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  if (!approval) return null

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!reason.trim()) {
      setError(t('findingApprovals.selfApprove.error.reason', 'Give a reason.'))
      return
    }
    setSaving(true)
    setError(null)
    try {
      const res = await selfApproveFindingApproval(approval.id, {
        reason: reason.trim(),
        code: code.trim(),
      })
      toast.success(
        res?.end_shortened
          ? t(
              'findingApprovals.selfApprove.doneShortened',
              'Approved. The acceptance was shortened to the limit for a self-approval.'
            )
          : t('findingApprovals.selfApprove.done', 'Approved')
      )
      onApproved?.()
      onOpenChange(false)
    } catch (err) {
      setError(selfApproveErrorMessage(t, err))
      setCode('')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {t('findingApprovals.selfApprove.title', 'Approve your own request')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'findingApprovals.selfApprove.description',
              'Nobody else in your organization can decide this request. As its only member and owner you may approve it yourself.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form method="post" id={formId} onSubmit={submit} className="space-y-4">
            <ul className="list-disc space-y-1 ps-5 text-sm text-muted-foreground">
              <li>
                {t(
                  'findingApprovals.selfApprove.audited',
                  'It is recorded in the audit log and marked self-approved everywhere.'
                )}
              </li>
              <li>
                {t(
                  'findingApprovals.selfApprove.told',
                  "Your organization's notification channels and its backup contact are told."
                )}
              </li>
              <li>
                {t(
                  'findingApprovals.selfApprove.limit',
                  'An accepted risk ends within 7 days (P0 or known exploited), 45 days (P1) or 90 days.'
                )}
              </li>
            </ul>
            {error && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                <span>{error}</span>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor={`${formId}-reason`}>
                {t(
                  'findingApprovals.selfApprove.reasonLabel',
                  'Why may it take effect without a second person?'
                )}
              </Label>
              <Textarea
                id={`${formId}-reason`}
                rows={3}
                maxLength={MAX_REASON}
                required
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${formId}-code`}>
                {t('findingApprovals.selfApprove.codeLabel', 'Code from your authenticator app')}
              </Label>
              <Input
                id={`${formId}-code`}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                required
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\s/g, ''))}
                className="w-40"
              />
            </div>
          </form>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            {t('findingApprovals.cancel', 'Cancel')}
          </Button>
          <Button
            type="submit"
            form={formId}
            disabled={saving || !reason.trim() || code.length < 6}
          >
            {saving ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <ShieldCheck className="me-2 h-4 w-4" aria-hidden />
            )}
            {t('findingApprovals.selfApprove.submit', 'Approve')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
