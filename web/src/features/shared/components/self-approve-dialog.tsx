'use client'

/**
 * An owner approves their own pending request (an exposure disposition or a
 * suppression rule) when nobody else in the organization can approve it.
 * The API decides whether that is allowed; this dialog asks for a reason
 * and a fresh code from the owner's authenticator app. The approval is
 * audited at critical severity, and a refused attempt is audited too.
 */

import { useId, useState } from 'react'
import { AlertTriangle, Loader2, ShieldCheck } from 'lucide-react'
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
import { getErrorMessage } from '@/lib/api/error-handler'

interface SelfApproveDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** What is being approved, shown in the description (plain text). */
  subject: string
  /** Sends the approval; throws on refusal. */
  onSubmit: (reason: string, code: string) => Promise<void>
}

export function SelfApproveDialog({
  open,
  onOpenChange,
  subject,
  onSubmit,
}: SelfApproveDialogProps) {
  const { t } = useTranslation()
  const formId = useId()
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const close = (next: boolean) => {
    if (!next) {
      setReason('')
      setCode('')
      setError(null)
    }
    onOpenChange(next)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!reason.trim() || !code.trim()) return
    setSaving(true)
    setError(null)
    try {
      await onSubmit(reason.trim(), code.trim())
      close(false)
    } catch (err) {
      setError(
        getErrorMessage(err, t('components.selfApprove.failed', 'Could not approve the request.'))
      )
      setCode('')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('components.selfApprove.title', 'Approve your own request')}</DialogTitle>
          <DialogDescription>
            {t(
              'components.selfApprove.description',
              'Nobody else in your organization can approve "{subject}". As the owner you may approve it yourself with a reason and a code from your authenticator app. It is recorded in the audit log.',
              { subject }
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form method="post" id={formId} onSubmit={submit} className="space-y-4">
            {error && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor={`${formId}-reason`}>
                {t(
                  'components.selfApprove.reason',
                  'Why may it take effect without a second person?'
                )}
              </Label>
              <Textarea
                id={`${formId}-reason`}
                rows={3}
                maxLength={500}
                required
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${formId}-code`}>
                {t('components.selfApprove.code', 'Code from your authenticator app')}
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
          <Button variant="outline" onClick={() => close(false)} disabled={saving}>
            {t('components.selfApprove.cancel', 'Cancel')}
          </Button>
          <Button type="submit" form={formId} disabled={saving || !reason.trim() || !code}>
            {saving ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <ShieldCheck className="me-2 h-4 w-4" />
            )}
            {t('components.selfApprove.submit', 'Approve')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
