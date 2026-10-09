'use client'

import { useId, useState, type FormEvent, type ReactNode } from 'react'
import { Loader2 } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '../api/admin-client'

/** Shortest reason the console accepts for a sensitive action. */
export const REASON_MIN = 10
export const REASON_MAX = 500

type Translate = (key: string, fallback: string, vars?: Record<string, string | number>) => string

/**
 * What a refused step-up action tells the administrator: a missing code and a
 * role that may not act get their own words; any other refusal (a rejected or
 * reused code, a missing reason) shows the API's message.
 */
export function stepUpErrorMessage(err: unknown, t: Translate): string {
  if (!(err instanceof AdminApiError))
    return t('admin.confirm.failed', 'The action failed. Try again.')
  if (err.code === 'STEP_UP_REQUIRED')
    return t('admin.confirm.codeRequired', 'Enter a fresh code from your authenticator.')
  if (err.status === 403)
    return t('admin.confirm.roleRefused', 'Your console role cannot do this. Ask a super admin.')
  return err.message
}

export interface AdminConfirmProof {
  /** Why the administrator acts; kept in the admin audit row. */
  reason: string
  /** A fresh console authenticator code (step-up), when asked for. */
  totp_code?: string
}

export interface AdminConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: ReactNode
  confirmLabel: string
  /** Red confirm button for an action that takes something away. */
  destructive?: boolean
  /** Ask for a fresh authenticator code too (the API demands step-up). */
  requireCode?: boolean
  /** Extra fields above the reason (e.g. the new owner's email). */
  children?: ReactNode
  /** False while the extra fields are not complete. */
  canSubmit?: boolean
  onConfirm: (proof: AdminConfirmProof) => Promise<void>
}

/**
 * The console's one confirmation for a sensitive action: what will happen, a
 * required reason (it goes to the admin audit log), and, when the API demands
 * step-up, a fresh authenticator code. The API's refusal is shown as is; the
 * dialog stays open so the administrator can correct and retry.
 */
export function AdminConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive,
  requireCode,
  children,
  canSubmit = true,
  onConfirm,
}: AdminConfirmDialogProps) {
  const { t } = useTranslation()
  const reasonId = useId()
  const codeId = useId()
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const reasonOk = reason.trim().length >= REASON_MIN && reason.trim().length <= REASON_MAX
  const codeOk = !requireCode || /^\d{6}$/.test(code)

  const reset = () => {
    setReason('')
    setCode('')
    setError(null)
    setBusy(false)
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!reasonOk || !codeOk || !canSubmit) return
    setBusy(true)
    setError(null)
    try {
      await onConfirm({ reason: reason.trim(), ...(requireCode ? { totp_code: code } : {}) })
      reset()
      onOpenChange(false)
    } catch (err) {
      setError(stepUpErrorMessage(err, t))
      // A used code cannot be replayed: clear it so the next one is typed.
      setCode('')
      setBusy(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset()
        onOpenChange(next)
      }}
    >
      <DialogContent>
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription asChild>
              <div className="space-y-2 text-sm text-muted-foreground">{description}</div>
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            {children}
            <div className="space-y-1.5">
              <Label htmlFor={reasonId}>{t('admin.confirm.reason', 'Reason')}</Label>
              <Textarea
                id={reasonId}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={REASON_MAX}
                rows={3}
                placeholder={t(
                  'admin.confirm.reasonPlaceholder',
                  'Ticket or request and why, e.g. "Support case 4411: owner left the company"'
                )}
                aria-describedby={`${reasonId}-hint`}
                required
              />
              <p id={`${reasonId}-hint`} className="text-xs text-muted-foreground">
                {t(
                  'admin.confirm.reasonHint',
                  'At least {min} characters. Kept in the administrator audit log.',
                  { min: REASON_MIN }
                )}
              </p>
            </div>
            {requireCode && (
              <div className="space-y-1.5">
                <Label htmlFor={codeId}>
                  {t('admin.confirm.code', 'Code from your authenticator')}
                </Label>
                <Input
                  id={codeId}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  className="w-36 font-mono tracking-widest"
                  required
                />
              </div>
            )}
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button
              type="submit"
              variant={destructive ? 'destructive' : 'default'}
              disabled={busy || !reasonOk || !codeOk || !canSubmit}
            >
              {busy && <Loader2 className="me-2 size-4 animate-spin" />}
              {confirmLabel}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
