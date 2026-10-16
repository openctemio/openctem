'use client'

import { useEffect, useId, useState, type FormEvent } from 'react'
import { Loader2, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { adminIdPInfo, adminSignIn } from '@/features/admin-console/api/use-admin-session'
import { AdminApiError } from '@/features/admin-console/api/admin-client'
import { TotpStepForm, adminErrorMessage } from '@/features/admin-console/components/totp-step-form'
import { IdPSignInButton } from '@/features/admin-console/components/idp-sign-in-button'
import { TurnstileWidget } from '@/features/auth/components/turnstile-widget'
import { useAuthProviders } from '@/features/auth/api/use-auth-providers'
import { nextFromLocation } from '@/features/admin-console/lib/console-navigation'
import type { AdminIdPInfo, AdminLoginResult } from '@/features/admin-console/types'

/**
 * Platform administrator sign-in (RFC-022). The console signs in on its own,
 * on its own origin, with no tenant session involved:
 * - the account's email and password, then the code from the console
 *   authenticator (or its enrollment on first use);
 * - or the administrators' own identity provider, when one is configured
 *   (never an organization's): the browser goes to the IdP and comes back to
 *   /admin/login/callback.
 */
export default function AdminSignInPage() {
  const { t } = useTranslation()
  const emailId = useId()
  const passwordId = useId()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [idp, setIdp] = useState<AdminIdPInfo | null>(null)
  const [idpRequired, setIdpRequired] = useState(false)
  const [step, setStep] = useState<AdminLoginResult | null>(null)
  // After repeated failed sign-ins the API asks for a security check
  // (CAPTCHA_REQUIRED); it is then shown and its token sent along.
  const [captchaRequired, setCaptchaRequired] = useState(false)
  const [captchaToken, setCaptchaToken] = useState('')
  const [captchaReset, setCaptchaReset] = useState(0)
  const { data: authProviders } = useAuthProviders(undefined, captchaRequired)

  useEffect(() => {
    let live = true
    adminIdPInfo()
      .then((info) => {
        if (live && info.enabled) setIdp(info)
      })
      .catch(() => undefined)
    return () => {
      live = false
    }
  }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!email.trim() || !password) return
    setBusy(true)
    setError(null)
    try {
      setStep(await adminSignIn(email.trim(), password, captchaRequired ? captchaToken : undefined))
      setPassword('')
    } catch (err) {
      setPassword('')
      if (captchaRequired) setCaptchaReset((n) => n + 1)
      if (err instanceof AdminApiError && err.code === 'CAPTCHA_REQUIRED') {
        setCaptchaRequired(true)
        setError(t('admin.login.captchaRequired', 'Complete the security check and try again.'))
      } else if (err instanceof AdminApiError && err.status === 401) {
        setError(t('admin.login.wrongCredentials', 'Wrong email or password.'))
      } else if (err instanceof AdminApiError && err.code === 'IDP_SIGN_IN_REQUIRED') {
        setIdpRequired(true)
        setError(
          t(
            'admin.login.idpRequired',
            'Administrators sign in with the identity provider. Password sign-in is for break-glass accounts only.'
          )
        )
      } else {
        setError(
          adminErrorMessage(err, t('admin.login.unreachable', 'The console could not be reached.'))
        )
      }
    } finally {
      setBusy(false)
    }
  }

  const backToPassword = () => {
    setStep(null)
    setError(null)
  }

  const enrolling = step?.status === 'mfa_enrollment_required'

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-xl">
          <ShieldCheck className="size-5 text-muted-foreground" />
          {t('admin.login.title', 'Platform administration')}
        </CardTitle>
        <CardDescription>
          {step
            ? enrolling
              ? t(
                  'admin.login.enroll',
                  'Set up two-step verification. It is required for every administrator.'
                )
              : t(
                  'admin.login.code',
                  'Enter the 6-digit code from your authenticator app to continue.'
                )
            : t('admin.login.description', 'Sign in to administer this installation.')}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {step ? (
          <TotpStepForm
            step={step}
            disabled={busy}
            onSwitchAccount={backToPassword}
            onVerified={() => {
              // Full navigation so the new session cookies are used from the start.
              window.location.href = nextFromLocation()
            }}
          />
        ) : (
          <div className="space-y-4">
            {idp && (
              <>
                <IdPSignInButton displayName={idp.display_name} next={nextFromLocation()} />
                <p className="text-center text-xs text-muted-foreground">
                  {t('admin.login.or', 'or sign in with your password')}
                </p>
              </>
            )}
            <form method="post" onSubmit={submit} className="space-y-3" noValidate>
              <div className="space-y-1.5">
                <Label htmlFor={emailId}>{t('admin.login.email', 'Email')}</Label>
                <Input
                  id={emailId}
                  type="email"
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  autoFocus={!idp}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor={passwordId}>{t('admin.login.password', 'Password')}</Label>
                <Input
                  id={passwordId}
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              {captchaRequired && authProviders?.captcha_site_key && (
                <TurnstileWidget
                  siteKey={authProviders.captcha_site_key}
                  onToken={setCaptchaToken}
                  resetSignal={captchaReset}
                />
              )}
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              {idpRequired && idp && (
                <IdPSignInButton displayName={idp.display_name} next={nextFromLocation()} />
              )}
              <Button
                type="submit"
                className="w-full"
                disabled={busy || !email.trim() || !password}
              >
                {busy && <Loader2 className="me-2 size-4 animate-spin" />}
                {t('admin.login.submit', 'Continue')}
              </Button>
            </form>
            {idp && (
              <p className="text-xs text-muted-foreground">
                {t(
                  'admin.login.breakGlassNote',
                  'Password sign-in is for break-glass (emergency) accounts when the identity provider is required.'
                )}
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
