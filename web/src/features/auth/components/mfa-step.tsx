/**
 * Second login step.
 *
 * - purpose "verify": the user has 2FA on; ask for an authenticator code or a
 *   recovery code.
 * - purpose "enroll": an organization the user belongs to requires 2FA and the
 *   user has not set it up; enroll an authenticator, show the recovery codes
 *   once, then continue.
 *
 * The challenge itself lives in an httpOnly cookie set by loginAction; this
 * component never sees it.
 */

'use client'

import { useEffect, useRef, useState, useTransition } from 'react'
import { ArrowLeft, Loader2, ShieldCheck } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import {
  ACCOUNT_RECOVERY_CODE,
  RecoveryCodesPanel,
  SecretKey,
  TOTP_CODE_LENGTH,
  TotpQrCode,
  VerificationCodeInput,
} from '@/components/security'
import { useTranslation } from '@/context/i18n-provider'

import {
  cancelMfaAction,
  confirmMfaEnrollmentAction,
  finishMfaEnrollmentAction,
  startMfaEnrollmentAction,
  verifyMfaAction,
  type LoginResult,
  type MfaPurpose,
} from '../actions/local-auth-actions'

interface MfaStepProps {
  purpose: MfaPurpose
  /** Called with a completed login result (session issued). */
  onDone: (result: LoginResult) => void
  /** Back to the password form, optionally with a reason to show. */
  onCancel: (message?: string) => void
  /** Organizations that require the second factor (enroll), named on the screen. */
  orgs?: string[]
  /** Label of the back button (default: back to sign in). */
  backLabel?: string
}

// The challenge expired, was used up, or the cookie is gone: only a fresh
// password login helps.
const RESTART_PATTERN = /sign in again|enter your password again|expired/i

/**
 * A completed second factor: the session was issued, or the only memberships
 * left are organizations waiting for deletion that the user owns (the login
 * form then offers to cancel the deletion). Both only happen after the API
 * accepted the second factor.
 */
function isCompleted(result: LoginResult): boolean {
  return result.success || (result.pendingDeletion?.length ?? 0) > 0
}

export function MfaStep({ purpose, onDone, onCancel, orgs, backLabel }: MfaStepProps) {
  return purpose === 'enroll' ? (
    <EnrollStep onDone={onDone} onCancel={onCancel} orgs={orgs} backLabel={backLabel} />
  ) : (
    <VerifyStep onDone={onDone} onCancel={onCancel} backLabel={backLabel} />
  )
}

/** "Required by Acme" or "Required by Acme and 2 more". */
function RequiredBy({ orgs }: { orgs?: string[] }) {
  const { t } = useTranslation()
  if (!orgs || orgs.length === 0) return null
  const [first, ...rest] = orgs
  return (
    <p className="text-sm font-medium">
      {rest.length === 0
        ? t('auth.mfa.requiredBy', undefined, { org: first })
        : t('auth.mfa.requiredByMore', undefined, { org: first, count: rest.length })}
    </p>
  )
}

function BackButton({ onCancel, label }: { onCancel: () => void; label?: string }) {
  const { t } = useTranslation()
  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className="justify-self-start px-0"
      onClick={async () => {
        await cancelMfaAction()
        onCancel()
      }}
    >
      <ArrowLeft className="h-4 w-4" />
      {label ?? t('auth.common.backToSignIn', 'Back to sign in')}
    </Button>
  )
}

function VerifyStep({ onDone, onCancel, backLabel }: Omit<MfaStepProps, 'purpose' | 'orgs'>) {
  const { t } = useTranslation()
  const [useRecovery, setUseRecovery] = useState(false)
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  const complete = (code: string) =>
    code.length === (useRecovery ? ACCOUNT_RECOVERY_CODE.length : TOTP_CODE_LENGTH)
  const canSubmit = complete(value)

  function send(code: string) {
    if (!complete(code) || isPending) return
    setError(null)
    startTransition(async () => {
      const result = await verifyMfaAction(useRecovery ? { recoveryCode: code } : { code })
      if (isCompleted(result)) {
        onDone(result)
        return
      }
      const msg = result.error || t('auth.mfa.verifyFailed', 'Verification failed')
      if (RESTART_PATTERN.test(msg)) {
        onCancel(msg)
        return
      }
      setError(msg)
      setValue('')
    })
  }

  function submit(e: React.FormEvent) {
    e.preventDefault()
    send(value)
  }

  return (
    <form
      method="post"
      onSubmit={submit}
      className="grid gap-3"
      aria-label={t('auth.mfa.verifyFormLabel', 'Two-factor verification')}
    >
      <div className="space-y-1">
        <h2 className="text-base font-semibold">
          {t('auth.mfa.title', 'Two-factor authentication')}
        </h2>
        <p className="text-sm text-muted-foreground">
          {useRecovery
            ? t('auth.mfa.recoveryHint', 'Enter one of your recovery codes. Each code works once.')
            : t('auth.mfa.codeHint', 'Enter the 6-digit code from your authenticator app.')}
        </p>
      </div>

      <VerificationCodeInput
        key={useRecovery ? 'recovery' : 'totp'}
        id="mfa-code"
        label={
          useRecovery
            ? t('auth.mfa.recoveryCodeLabel', 'Recovery code')
            : t('auth.mfa.codeLabel', 'Authentication code')
        }
        mode={useRecovery ? 'alphanumeric' : 'numeric'}
        length={useRecovery ? ACCOUNT_RECOVERY_CODE.length : TOTP_CODE_LENGTH}
        groups={useRecovery ? [...ACCOUNT_RECOVERY_CODE.groups] : undefined}
        autoFocus
        value={value}
        onChange={setValue}
        onComplete={send}
        disabled={isPending}
        error={error}
      />

      <Button type="submit" disabled={!canSubmit || isPending}>
        {isPending ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <ShieldCheck className="h-4 w-4" />
        )}
        {t('auth.mfa.verify', 'Verify')}
      </Button>

      <Button
        type="button"
        variant="link"
        size="sm"
        className="h-auto px-0"
        onClick={() => {
          setUseRecovery((v) => !v)
          setValue('')
          setError(null)
        }}
      >
        {useRecovery
          ? t('auth.mfa.useApp', 'Use your authenticator app instead')
          : t('auth.mfa.useRecovery', 'Use a recovery code instead')}
      </Button>

      <BackButton onCancel={() => onCancel()} label={backLabel} />
    </form>
  )
}

function EnrollStep({ onDone, onCancel, orgs, backLabel }: Omit<MfaStepProps, 'purpose'>) {
  const { t } = useTranslation()
  // Read through a ref so the start-once effect below does not depend on t.
  const startFailedRef = useRef(
    t('auth.mfa.startFailed', 'Could not start two-factor setup. Please sign in again.')
  )
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [finished, setFinished] = useState<LoginResult | null>(null)
  const [saved, setSaved] = useState(false)
  const [isPending, startTransition] = useTransition()

  // Each start issues a new secret and replaces the previous one, so it must
  // run exactly once (React StrictMode runs effects twice in development).
  // onCancel is read through a ref so a new callback identity from the parent
  // never restarts enrollment.
  const started = useRef(false)
  const onCancelRef = useRef(onCancel)
  useEffect(() => {
    onCancelRef.current = onCancel
  }, [onCancel])
  useEffect(() => {
    if (started.current) return
    started.current = true
    startMfaEnrollmentAction().then((res) => {
      if (res.success && res.secret && res.otpauthUri) {
        setSetup({ secret: res.secret, uri: res.otpauthUri })
      } else {
        onCancelRef.current(res.error || startFailedRef.current)
      }
    })
  }, [])

  function sendCode(value: string) {
    if (value.length !== TOTP_CODE_LENGTH || !setup || isPending) return
    setError(null)
    startTransition(async () => {
      const result = await confirmMfaEnrollmentAction(value)
      if (result.success) {
        setFinished(result)
        return
      }
      const msg = result.error || t('auth.mfa.verifyFailed', 'Verification failed')
      if (RESTART_PATTERN.test(msg)) {
        onCancel(msg)
        return
      }
      setError(msg)
      setCode('')
    })
  }

  function confirm(e: React.FormEvent) {
    e.preventDefault()
    sendCode(code)
  }

  if (finished) {
    return (
      <div className="grid gap-4">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">
            {t('auth.mfa.saveCodesTitle', 'Save your recovery codes')}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t(
              'auth.mfa.saveCodesBody',
              'Two-factor authentication is on. If you lose your authenticator, a recovery code is the only way back into your account.'
            )}
          </p>
        </div>
        <RecoveryCodesPanel
          codes={finished.recoveryCodes ?? []}
          accountLabel={finished.user?.email}
        />
        <div className="flex items-center gap-2">
          <Checkbox
            id="codes-saved"
            checked={saved}
            onCheckedChange={(v) => setSaved(v === true)}
          />
          <Label htmlFor="codes-saved" className="font-normal">
            {t('auth.mfa.codesSaved', 'I have saved my recovery codes')}
          </Label>
        </div>
        <Button
          type="button"
          disabled={!saved || isPending}
          onClick={() =>
            startTransition(async () => {
              const result = await finishMfaEnrollmentAction()
              if (isCompleted(result)) {
                onDone(result)
              } else {
                onCancel(result.error)
              }
            })
          }
        >
          {isPending && <Loader2 className="h-4 w-4 animate-spin" />}
          {t('auth.mfa.continue', 'Continue')}
        </Button>
      </div>
    )
  }

  return (
    <form
      method="post"
      onSubmit={confirm}
      className="grid gap-4"
      aria-label={t('auth.mfa.enrollTitle', 'Set up two-factor authentication')}
    >
      <div className="space-y-1">
        <h2 className="text-base font-semibold">
          {t('auth.mfa.enrollTitle', 'Set up two-factor authentication')}
        </h2>
        <p className="text-sm text-muted-foreground">
          {t(
            'auth.mfa.enrollBody',
            'Your organization requires two-factor authentication. Scan the QR code with an authenticator app, then enter the 6-digit code it shows.'
          )}
        </p>
        <RequiredBy orgs={orgs} />
      </div>

      {setup ? (
        <div className="flex flex-col items-center gap-3">
          <TotpQrCode uri={setup.uri} size={176} />
          <SecretKey secret={setup.secret} />
        </div>
      ) : (
        <Skeleton className="mx-auto h-44 w-44" />
      )}

      <VerificationCodeInput
        id="enroll-code"
        label={t('auth.mfa.codeLabel', 'Authentication code')}
        value={code}
        onChange={setCode}
        onComplete={sendCode}
        disabled={!setup || isPending}
        error={error}
      />

      <Button type="submit" disabled={!setup || code.length !== TOTP_CODE_LENGTH || isPending}>
        {isPending ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <ShieldCheck className="h-4 w-4" />
        )}
        {t('auth.mfa.turnOn', 'Turn on and continue')}
      </Button>

      <BackButton onCancel={() => onCancel()} label={backLabel} />
    </form>
  )
}
