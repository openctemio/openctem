'use client'

import { useCallback, useState, useTransition } from 'react'
import Link from 'next/link'
import { Loader2, MailCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { submitAccessRequestAction } from '../actions/local-auth-actions'
import { useAuthProviders } from '../api/use-auth-providers'
import { TurnstileWidget } from './turnstile-widget'
import { isSignupNotAvailable } from '../lib/signup-outcome'

const MAX_COMPANY = 200
const MAX_NOTE = 1000

/**
 * Request access (sign-up closed, requests allowed). The answer is the same
 * whatever happens to the request, so the page never says whether the email
 * or the company is known.
 */
export function RequestAccessForm() {
  const { t } = useTranslation()
  const [company, setCompany] = useState('')
  const [email, setEmail] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [sent, setSent] = useState(false)
  const [isPending, startTransition] = useTransition()
  const { data: providers } = useAuthProviders()
  const siteKey = providers?.captcha_site_key ?? ''
  const [captchaToken, setCaptchaToken] = useState('')
  const [captchaFailed, setCaptchaFailed] = useState(false)
  const onCaptchaToken = useCallback((token: string) => setCaptchaToken(token), [])
  const onCaptchaError = useCallback(() => setCaptchaFailed(true), [])

  const valid =
    (!siteKey || captchaToken !== '') &&
    company.trim().length > 0 &&
    company.length <= MAX_COMPANY &&
    note.length <= MAX_NOTE &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())

  function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!valid) return
    setError(null)
    startTransition(async () => {
      const res = await submitAccessRequestAction({
        company: company.trim(),
        email: email.trim(),
        note: note.trim(),
        ...(siteKey ? { captcha_token: captchaToken } : {}),
      })
      if (res.success) {
        setSent(true)
      } else if (isSignupNotAvailable(res.code)) {
        setError(t('auth.requestAccess.closed', 'Requests are not accepted at the moment.'))
      } else {
        setError(res.error)
        // A token is single use: ask for a new one.
        setCaptchaToken('')
      }
    })
  }

  if (sent) {
    return (
      <Card className="mx-auto w-full max-w-md">
        <CardHeader className="items-center text-center">
          <MailCheck className="size-8 text-muted-foreground" aria-hidden />
          <CardTitle>{t('auth.requestAccess.title', 'Request access')}</CardTitle>
          <CardDescription>
            {t(
              'auth.requestAccess.sent',
              'Thanks. If your request is approved, you will get an email at the address you entered.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-center text-sm text-muted-foreground">
          <p>
            {t(
              'auth.requestAccess.checkEmail',
              'If email is set up, we sent you a link to confirm the request.'
            )}
          </p>
          <Button asChild variant="outline">
            <Link href="/login">{t('auth.notSetUp.backToSignIn', 'Back to sign in')}</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="mx-auto w-full max-w-md">
      <CardHeader>
        <CardTitle>{t('auth.requestAccess.title', 'Request access')}</CardTitle>
        <CardDescription>
          {t(
            'auth.requestAccess.description',
            'Tell us about your organization. An administrator reviews every request.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          <div className="space-y-2">
            <Label htmlFor="ra-company">{t('auth.requestAccess.company', 'Company')}</Label>
            <Input
              id="ra-company"
              value={company}
              onChange={(e) => setCompany(e.target.value)}
              maxLength={MAX_COMPANY}
              autoComplete="organization"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ra-email">{t('auth.requestAccess.email', 'Work email')}</Label>
            <Input
              id="ra-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ra-note">
              {t('auth.requestAccess.note', 'What would you like to use it for? (optional)')}
            </Label>
            <Textarea
              id="ra-note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              maxLength={MAX_NOTE}
              rows={3}
            />
          </div>
          {siteKey && (
            <div className="space-y-1">
              <TurnstileWidget
                key={error ?? 'captcha'}
                siteKey={siteKey}
                onToken={onCaptchaToken}
                onError={onCaptchaError}
              />
              {captchaFailed && (
                <p className="text-center text-xs text-muted-foreground">
                  {t(
                    'auth.requestAccess.captchaFailed',
                    'The security check could not load. Allow challenges.cloudflare.com, or try another network.'
                  )}
                </p>
              )}
            </div>
          )}
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <Button type="submit" className="w-full" disabled={!valid || isPending}>
            {isPending && <Loader2 className="me-2 size-4 animate-spin" />}
            {t('auth.requestAccess.submit', 'Send request')}
          </Button>
          <div className="text-center">
            <Link href="/login" className="text-sm text-muted-foreground hover:underline">
              {t('auth.notSetUp.backToSignIn', 'Back to sign in')}
            </Link>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
