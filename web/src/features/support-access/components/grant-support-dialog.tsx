'use client'

/**
 * The owner's "Grant access" dialog (api RFC-063). The API checks every field
 * again (and that the email names an active support administrator); the
 * checks here only save a round trip. Creating a grant needs a recent
 * re-authentication: the shared API client shows the re-auth dialog on
 * STEP_UP_REQUIRED and retries, so this form just awaits the call.
 */

import { useState, type FormEvent } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
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

import {
  createSupportGrant,
  SUPPORT_DEFAULT_DURATION,
  SUPPORT_DURATIONS,
  SUPPORT_REASON_MAX,
  SUPPORT_REASON_MIN,
  SUPPORT_SCOPES,
  type SupportScope,
} from '../api/use-support-access'

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function GrantSupportDialog({
  open,
  onOpenChange,
  onGranted,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onGranted: () => void
}) {
  const { t } = useTranslation()
  const [email, setEmail] = useState('')
  const [scopes, setScopes] = useState<SupportScope[]>([...SUPPORT_SCOPES])
  const [duration, setDuration] = useState<number>(SUPPORT_DEFAULT_DURATION)
  const [reason, setReason] = useState('')
  const [caseRef, setCaseRef] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [busy, setBusy] = useState(false)
  const [serverError, setServerError] = useState<string | null>(null)

  const reasonLen = reason.trim().length
  const errors = {
    email: EMAIL_RE.test(email.trim())
      ? null
      : t('supportAccess.grant.emailInvalid', 'Enter the support administrator’s email address.'),
    scopes:
      scopes.length > 0 ? null : t('supportAccess.grant.scopesRequired', 'Choose at least one.'),
    reason:
      reasonLen >= SUPPORT_REASON_MIN && reasonLen <= SUPPORT_REASON_MAX
        ? null
        : t('supportAccess.grant.reasonLength', 'Write {min} to {max} characters.', {
            min: SUPPORT_REASON_MIN,
            max: SUPPORT_REASON_MAX,
          }),
  }
  const invalid = Boolean(errors.email || errors.scopes || errors.reason)

  function reset() {
    setEmail('')
    setScopes([...SUPPORT_SCOPES])
    setDuration(SUPPORT_DEFAULT_DURATION)
    setReason('')
    setCaseRef('')
    setSubmitted(false)
    setServerError(null)
  }

  function toggleScope(scope: SupportScope, on: boolean) {
    setScopes((prev) =>
      on
        ? SUPPORT_SCOPES.filter((s) => s === scope || prev.includes(s))
        : prev.filter((s) => s !== scope)
    )
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setSubmitted(true)
    setServerError(null)
    if (invalid) return
    setBusy(true)
    try {
      await createSupportGrant({
        admin_email: email.trim(),
        scopes,
        duration_hours: duration,
        reason: reason.trim(),
        case_ref: caseRef.trim() || undefined,
      })
      toast.success(t('supportAccess.grant.done', 'Support access granted'))
      reset()
      onOpenChange(false)
      onGranted()
    } catch (err) {
      setServerError(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) reset()
        onOpenChange(o)
      }}
    >
      <DialogContent size="md">
        <DialogForm onSubmit={submit} noValidate>
          <DialogHeader>
            <DialogTitle>{t('supportAccess.grant.title', 'Grant support access')}</DialogTitle>
            <DialogDescription>
              {t(
                'supportAccess.grant.description',
                'The administrator can read the data you choose, read-only, until the time runs out or you revoke it. You will be asked to confirm your identity.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            {serverError && (
              <Alert variant="destructive">
                <AlertDescription>{serverError}</AlertDescription>
              </Alert>
            )}
            <div className="space-y-2">
              <Label htmlFor="support-admin-email">
                {t('supportAccess.grant.email', 'Support administrator’s email')}
              </Label>
              <Input
                id="support-admin-email"
                type="email"
                autoComplete="off"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                aria-invalid={submitted && !!errors.email}
                aria-describedby="support-admin-email-hint"
              />
              <p id="support-admin-email-hint" className="text-xs text-muted-foreground">
                {submitted && errors.email ? (
                  <span className="text-destructive">{errors.email}</span>
                ) : (
                  t(
                    'supportAccess.grant.emailHint',
                    'The person from platform support who asked for access. Only an active support administrator can be named.'
                  )
                )}
              </p>
            </div>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">
                {t('supportAccess.grant.scopes', 'Data they can read')}
              </legend>
              <div className="flex flex-wrap gap-4">
                {SUPPORT_SCOPES.map((s) => (
                  <label key={s} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={scopes.includes(s)}
                      onCheckedChange={(c) => toggleScope(s, c === true)}
                      aria-label={t(`supportAccess.scopeLabel.${s}`, s)}
                    />
                    {t(`supportAccess.scopeLabel.${s}`, s)}
                  </label>
                ))}
              </div>
              {submitted && errors.scopes && (
                <p className="text-xs text-destructive">{errors.scopes}</p>
              )}
            </fieldset>
            <div className="space-y-2">
              <Label htmlFor="support-duration">{t('supportAccess.grant.duration', 'For')}</Label>
              <Select value={String(duration)} onValueChange={(v) => setDuration(Number(v))}>
                <SelectTrigger id="support-duration" className="w-full sm:w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SUPPORT_DURATIONS.map((h) => (
                    <SelectItem key={h} value={String(h)}>
                      {h === 1
                        ? t('supportAccess.grant.hour', '1 hour')
                        : t('supportAccess.grant.hours', '{n} hours', { n: h })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="support-reason">{t('supportAccess.grant.reason', 'Reason')}</Label>
              <Textarea
                id="support-reason"
                rows={3}
                maxLength={SUPPORT_REASON_MAX}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                aria-invalid={submitted && !!errors.reason}
                aria-describedby="support-reason-hint"
              />
              <div
                id="support-reason-hint"
                className="flex justify-between gap-2 text-xs text-muted-foreground"
              >
                <span className={submitted && errors.reason ? 'text-destructive' : undefined}>
                  {submitted && errors.reason
                    ? errors.reason
                    : t(
                        'supportAccess.grant.reasonHint',
                        'What support should look at. It is kept in the audit log.'
                      )}
                </span>
                <span className="shrink-0 tabular-nums">
                  {reasonLen}/{SUPPORT_REASON_MAX}
                </span>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="support-case-ref">
                {t('supportAccess.grant.caseRef', 'Case reference (optional)')}
              </Label>
              <Input
                id="support-case-ref"
                maxLength={64}
                value={caseRef}
                onChange={(e) => setCaseRef(e.target.value)}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={busy}>
              {busy && <Loader2 className="size-4 animate-spin" aria-hidden="true" />}
              {t('supportAccess.grant.submit', 'Grant access')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
