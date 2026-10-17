'use client'

import { useState, type FormEvent } from 'react'
import { KeyRound, Loader2 } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { adminSignInWithKey, adminSignInWithRecoveryCode } from '../api/use-console-factors'
import { isWebAuthnSupported } from '../lib/webauthn'
import { securityKeyErrorMessage } from '../lib/security-key-errors'
import { TotpStepForm, adminErrorMessage, type TotpStep } from './totp-step-form'
import type { AdminIdentity, AdminSignInMethod } from '../types'

type Method = 'webauthn' | 'totp' | 'recovery'

export interface SecondFactorStepProps {
  step: TotpStep & { methods?: AdminSignInMethod[] }
  onVerified: (admin: AdminIdentity) => void
  onSwitchAccount?: () => void
  disabled?: boolean
}

/** What a sign-in without a `methods` list (the IdP callback) may use. */
const DEFAULT_METHODS: AdminSignInMethod[] = ['totp', 'recovery_code']

function initialMethod(step: SecondFactorStepProps['step'], methods: AdminSignInMethod[]): Method {
  if (step.status === 'mfa_enrollment_required') return 'totp'
  if (methods.includes('webauthn') && isWebAuthnSupported()) return 'webauthn'
  if (methods.includes('totp')) return 'totp'
  if (methods.includes('webauthn')) return 'webauthn'
  return 'recovery'
}

/**
 * The console's second step, shared by the password sign-in and the
 * identity-provider callback. A security key or passkey is the preferred
 * method; the authenticator app (when the console still allows it for this
 * administrator) and a one-time recovery code are the fallbacks. Enrollment
 * of the first factor stays the authenticator app.
 */
export function SecondFactorStep({
  step,
  onVerified,
  onSwitchAccount,
  disabled,
}: SecondFactorStepProps) {
  const { t } = useTranslation()
  const [methods, setMethods] = useState<AdminSignInMethod[]>(step.methods ?? DEFAULT_METHODS)
  const [method, setMethod] = useState<Method>(() => initialMethod(step, methods))
  const [notice, setNotice] = useState<string | null>(null)

  if (step.status === 'mfa_enrollment_required') {
    return (
      <TotpStepForm
        step={step}
        disabled={disabled}
        onVerified={onVerified}
        onSwitchAccount={onSwitchAccount}
      />
    )
  }

  const switchTo = (m: Method) => {
    setNotice(null)
    setMethod(m)
  }

  const others = (
    <div className="flex flex-col items-start gap-1 border-t pt-3">
      {method !== 'webauthn' && methods.includes('webauthn') && (
        <Button
          type="button"
          variant="link"
          className="h-auto px-0"
          onClick={() => switchTo('webauthn')}
        >
          {t('admin.login.useKey', 'Use security key or passkey')}
        </Button>
      )}
      {method !== 'totp' && methods.includes('totp') && (
        <Button
          type="button"
          variant="link"
          className="h-auto px-0"
          onClick={() => switchTo('totp')}
        >
          {t('admin.login.useAuthenticator', 'Use authenticator app')}
        </Button>
      )}
      {method !== 'recovery' && methods.includes('recovery_code') && (
        <Button
          type="button"
          variant="link"
          className="h-auto px-0"
          onClick={() => switchTo('recovery')}
        >
          {t('admin.login.useRecoveryCode', 'Use a recovery code')}
        </Button>
      )}
    </div>
  )

  return (
    <div className="space-y-4">
      {notice && (
        <Alert>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      )}
      {method === 'webauthn' && (
        <KeySignIn disabled={disabled} onVerified={onVerified} onSwitchAccount={onSwitchAccount} />
      )}
      {method === 'totp' && (
        <TotpStepForm
          step={step}
          disabled={disabled}
          onVerified={onVerified}
          onSwitchAccount={onSwitchAccount}
          onWebAuthnRequired={() => {
            // The console requires this administrator's security key: the
            // authenticator app is no longer offered.
            setMethods((m) => {
              const next = m.filter((x) => x !== 'totp')
              return next.includes('webauthn') ? next : ['webauthn', ...next]
            })
            setNotice(
              t(
                'admin.login.keyRequired',
                'The console requires your security key or passkey. The authenticator app is not accepted.'
              )
            )
            setMethod('webauthn')
          }}
        />
      )}
      {method === 'recovery' && (
        <RecoveryCodeForm
          disabled={disabled}
          onVerified={onVerified}
          onSwitchAccount={onSwitchAccount}
        />
      )}
      {others}
    </div>
  )
}

function KeySignIn({
  onVerified,
  onSwitchAccount,
  disabled,
}: {
  onVerified: (admin: AdminIdentity) => void
  onSwitchAccount?: () => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const supported = isWebAuthnSupported()

  const signIn = async () => {
    setBusy(true)
    setError(null)
    try {
      onVerified(await adminSignInWithKey())
    } catch (err) {
      setError(securityKeyErrorMessage(err, t))
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {t(
          'admin.login.keyHint',
          'Use the security key or passkey you registered for this console. Your browser will ask you to touch the key or confirm with your fingerprint, face or PIN.'
        )}
      </p>
      {!supported && (
        <Alert variant="destructive">
          <AlertDescription>
            {t(
              'admin.keys.unsupported',
              'This browser cannot use security keys or passkeys. Use a current browser.'
            )}
          </AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <Button
        type="button"
        className="w-full"
        autoFocus
        disabled={busy || disabled || !supported}
        onClick={() => void signIn()}
      >
        {busy ? (
          <Loader2 className="me-2 size-4 animate-spin" />
        ) : (
          <KeyRound className="me-2 size-4" />
        )}
        {t('admin.login.useKey', 'Use security key or passkey')}
      </Button>
      {onSwitchAccount && (
        <Button
          type="button"
          variant="ghost"
          className="w-full"
          disabled={busy || disabled}
          onClick={onSwitchAccount}
        >
          {t('admin.login.switchAccount', 'Sign in with a different account')}
        </Button>
      )}
    </div>
  )
}

function RecoveryCodeForm({
  onVerified,
  onSwitchAccount,
  disabled,
}: {
  onVerified: (admin: AdminIdentity) => void
  onSwitchAccount?: () => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onVerified(await adminSignInWithRecoveryCode(code.trim()))
    } catch (err) {
      setError(
        adminErrorMessage(
          err,
          t('admin.login.invalidRecoveryCode', 'Invalid or already used recovery code'),
          t('admin.login.tooMany', 'Too many attempts. Wait a minute and try again.')
        )
      )
      setCode('')
      setBusy(false)
    }
  }

  return (
    <form method="post" onSubmit={submit} className="space-y-4">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="space-y-2">
        <Label htmlFor="admin-recovery-code">
          {t('admin.login.recoveryCode', 'Recovery code')}
        </Label>
        <Input
          id="admin-recovery-code"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          required
          autoFocus
          maxLength={64}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          className="font-mono tracking-wider"
        />
        <p className="text-xs text-muted-foreground">
          {t(
            'admin.login.recoveryHint',
            'One of the recovery codes you saved when you set up your security keys. Each code works once.'
          )}
        </p>
      </div>
      <Button type="submit" className="w-full" disabled={busy || disabled || !code.trim()}>
        {busy && <Loader2 className="me-2 size-4 animate-spin" />}
        {t('admin.login.continue', 'Continue')}
      </Button>
      {onSwitchAccount && (
        <Button
          type="button"
          variant="ghost"
          className="w-full"
          disabled={busy || disabled}
          onClick={onSwitchAccount}
        >
          {t('admin.login.switchAccount', 'Sign in with a different account')}
        </Button>
      )}
    </form>
  )
}
