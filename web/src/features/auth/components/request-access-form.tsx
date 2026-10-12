'use client'

import { useState, useTransition } from 'react'
import Link from '@/components/link'
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
  const { data: authProviders } = useAuthProviders()
  const captchaSiteKey = authProviders?.captcha_site_key ?? ''
  const [captchaToken, setCaptchaToken] = useState('')
  const [captchaReset, setCaptchaReset] = useState(0)

  const valid =
    company.trim().length > 0 &&
    company.length <= MAX_COMPANY &&
    note.length <= MAX_NOTE &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) &&
    (!captchaSiteKey || captchaToken !== '')

  function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!valid) return
    setError(null)
    startTransition(async () => {
      const res = await submitAccessRequestAction({
        company: company.trim(),
        email: email.trim(),
        note: note.trim(),
        captchaToken: captchaToken || undefined,
      })
      if (captchaSiteKey) setCaptchaReset((n) => n + 1)
      if (res.success) {
        setSent(true)
      } else if (isSignupNotAvailable(res.code)) {
        setError(t('auth.requestAccess.closed', 'Requests are not accepted at the moment.'))
      } else if (res.code === 'CAPTCHA_FAILED') {
        setError(t('auth.captcha.failed', 'Complete the security check and try again.'))
      } else {
        setError(res.error)
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
        <form method="post" onSubmit={onSubmit} className="space-y-4" noValidate>
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
          {captchaSiteKey && (
            <TurnstileWidget
              siteKey={captchaSiteKey}
              onToken={setCaptchaToken}
              resetSignal={captchaReset}
            />
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
