'use client'

/**
 * An owner approves their own pending scope entry when nobody else can
 * (RFC-054 §7): an organization with a single owner. The API decides
 * whether it is allowed (`approval.self_approval_available`); the dialog
 * asks for a reason and a fresh code from the owner's authenticator app. It
 * is audited at high severity and every administrator is told.
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
import { invalidateScopeCache, selfApproveScopeTarget } from '../api/use-scope-api'
import type { ApiScopeTarget } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'

interface ScopeSelfApproveDialogProps {
  entry: ApiScopeTarget | null
  onOpenChange: (open: boolean) => void
}

export function ScopeSelfApproveDialog({ entry, onOpenChange }: ScopeSelfApproveDialogProps) {
  const { t } = useTranslation()
  const formId = useId()
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  if (!entry) return null

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!reason.trim()) {
      setError(t('scope.error.SELF_APPROVAL_REASON_REQUIRED'))
      return
    }
    setSaving(true)
    setError(null)
    try {
      await selfApproveScopeTarget(entry.id ?? '', {
        reason: reason.trim(),
        totp_code: code.trim(),
      })
      await invalidateScopeCache()
      toast.success(`${entry.pattern} is in effect`)
      onOpenChange(false)
    } catch (err) {
      setError(scopeErrorMessage(t, err, 'Could not approve the entry.'))
      setCode('')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Approve your own entry</DialogTitle>
          <DialogDescription>
            Nobody else in your organization can approve{' '}
            <code className="break-all">{entry.pattern}</code>. As an owner you may approve it
            yourself. This is recorded in the audit log and every administrator is told.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form id={formId} onSubmit={submit} className="space-y-4">
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
                Why may it take effect without a second person?
              </Label>
              <Textarea
                id={`${formId}-reason`}
                rows={3}
                maxLength={1000}
                required
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${formId}-code`}>Code from your authenticator app</Label>
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
            Cancel
          </Button>
          <Button type="submit" form={formId} disabled={saving || !reason.trim() || !code}>
            {saving ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <ShieldCheck className="me-2 h-4 w-4" />
            )}
            Approve
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
