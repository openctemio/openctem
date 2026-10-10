'use client'

/**
 * Emergency override: suspends one policy, or every policy of the
 * organization, for 15 minutes to 24 hours. Needs scans:windows:override
 * (owners and administrators), a reason and a current code from the
 * caller's authenticator app. It is audited and every owner and
 * administrator is notified. Bug-bounty program windows are never
 * suspended (the API enforces all of this; the dialog only explains it).
 */

import { useEffect, useState } from 'react'
import Link from '@/components/link'
import { AlertTriangle, Loader2, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import { createScanWindowOverride, invalidateScanWindows } from '../api/use-scan-windows'
import {
  apiErrorCode,
  WINDOW_OVERRIDE_INVALID_CODE,
  WINDOW_OVERRIDE_NEEDS_TOTP,
} from '../lib/decision'
import type { ScanWindowPolicy } from '../types'

export const MIN_REASON = 10
export const MAX_REASON = 500
/** Durations offered, in minutes (15 minutes to 24 hours). */
export const OVERRIDE_DURATIONS = [15, 30, 60, 120, 240, 480, 720, 1440]
const ALL = 'all'

function durationLabel(
  m: number,
  t: (k: string, f?: string, v?: Record<string, string | number>) => string
) {
  return m < 60
    ? t('scanWindows.override.minutes', '{n} minutes', { n: m })
    : m === 60
      ? t('scanWindows.override.hour', '1 hour')
      : t('scanWindows.override.hours', '{n} hours', { n: m / 60 })
}

interface OverrideDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  policies: ScanWindowPolicy[]
}

export function OverrideDialog({ open, onOpenChange, policies }: OverrideDialogProps) {
  const { t } = useTranslation()
  const [policyId, setPolicyId] = useState<string>(ALL)
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState('60')
  const [code, setCode] = useState('')
  const [error, setError] = useState<{ text: string; setup?: boolean } | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!open) return
    setPolicyId(ALL)
    setReason('')
    setDuration('60')
    setCode('')
    setError(null)
  }, [open])

  const reasonOk = reason.trim().length >= MIN_REASON && reason.trim().length <= MAX_REASON
  const codeOk = /^\d{6,8}$/.test(code)

  const submit = async () => {
    if (!reasonOk || !codeOk) return
    setSaving(true)
    setError(null)
    try {
      await createScanWindowOverride({
        policy_id: policyId === ALL ? undefined : policyId,
        reason: reason.trim(),
        duration_minutes: Number(duration),
        totp_code: code,
      })
      toast.success(t('scanWindows.override.started', 'Scan windows overridden'))
      await invalidateScanWindows()
      onOpenChange(false)
    } catch (err) {
      const c = apiErrorCode(err)
      if (c === WINDOW_OVERRIDE_NEEDS_TOTP) {
        setError({
          text: t(
            'scanWindows.override.needsTotp',
            'An override needs a code from an authenticator app, and your account has none. Set one up in account security, then try again.'
          ),
          setup: true,
        })
      } else if (c === WINDOW_OVERRIDE_INVALID_CODE) {
        setError({
          text: t(
            'scanWindows.override.invalidCode',
            'That code is not valid. Enter the current code from your authenticator app.'
          ),
        })
      } else {
        setError({
          text: getErrorMessage(
            err,
            t('scanWindows.override.failed', 'Could not override the scan windows.')
          ),
        })
      }
      setCode('')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('scanWindows.override.title', 'Override scan windows')}</DialogTitle>
          <DialogDescription>
            {t(
              'scanWindows.override.description',
              'Scans may run outside the chosen windows until the override ends. It is recorded in the audit log and every owner and administrator is notified. Bug-bounty program windows are never lifted.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <DialogBody className="space-y-4">
            {error && (
              <Alert variant="destructive" role="alert" data-testid="override-error">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <p>{error.text}</p>
                  {error.setup && (
                    <Link
                      href="/account/security"
                      className="font-medium underline underline-offset-2"
                    >
                      {t('scanWindows.override.setup', 'Open account security')}
                    </Link>
                  )}
                </AlertDescription>
              </Alert>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="override-policy">
                {t('scanWindows.override.policy', 'Windows to lift')}
              </Label>
              <Select value={policyId} onValueChange={setPolicyId}>
                <SelectTrigger id="override-policy">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>
                    {t('scanWindows.override.all', 'Every policy')}
                  </SelectItem>
                  {policies.map((p) => (
                    <SelectItem key={p.id} value={p.id ?? ''}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="override-duration">{t('scanWindows.override.duration', 'For')}</Label>
              <Select value={duration} onValueChange={setDuration}>
                <SelectTrigger id="override-duration" className="sm:w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {OVERRIDE_DURATIONS.map((m) => (
                    <SelectItem key={m} value={String(m)}>
                      {durationLabel(m, t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="override-reason">{t('scanWindows.override.reason', 'Reason')}</Label>
              <Textarea
                id="override-reason"
                rows={3}
                maxLength={MAX_REASON}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                aria-describedby="override-reason-hint"
              />
              <p id="override-reason-hint" className="text-xs text-muted-foreground">
                {t(
                  'scanWindows.override.reasonHint',
                  '{min} to {max} characters, kept in the audit log.',
                  {
                    min: MIN_REASON,
                    max: MAX_REASON,
                  }
                )}
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="override-code">
                {t('scanWindows.override.code', 'Code from your authenticator app')}
              </Label>
              <Input
                id="override-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                className="w-40"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" variant="destructive" disabled={saving || !reasonOk || !codeOk}>
              {saving ? (
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              ) : (
                <ShieldAlert className="h-4 w-4" aria-hidden />
              )}
              {t('scanWindows.override.submit', 'Override')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
