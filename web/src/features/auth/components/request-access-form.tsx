'use client'

import { useState, useTransition } from 'react'
import { Loader2 } from 'lucide-react'
import {
  EntryActions,
  EntryBackLink,
  EntryBanner,
  EntryCard,
  EntryHeader,
} from '@/components/entry'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { submitAccessRequestAction } from '../actions/local-auth-actions'
import { useAuthProviders } from '../api/use-auth-providers'
import { TurnstileWidget } from './turnstile-widget'
import { isSignupNotAvailable } from '../lib/signup-outcome'
import { authErrorText } from '../lib/auth-error-codes'

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
        // The words come from the API's code; the server's sentence is never shown.
        setError(
          authErrorText(
            res.code,
            t,
            t('auth.requestAccess.failed', 'Could not send the request. Try again in a minute.')
          )
        )
      }
    })
  }

  if (sent) {
    return (
      <EntryCard>
        <EntryHeader title={t('auth.requestAccess.title', 'Request access')} />
        <EntryBanner tone="ok">
          <p>
            {t(
              'auth.requestAccess.sent',
              'Thanks. If your request is approved, you will get an email at the address you entered.'
            )}
          </p>
          <p>
            {t(
              'auth.requestAccess.checkEmail',
              'If email is set up, we sent you a link to confirm the request.'
            )}
          </p>
        </EntryBanner>
        <EntryActions>
          <EntryBackLink />
        </EntryActions>
      </EntryCard>
    )
  }

  return (
    <EntryCard>
      <EntryHeader
        title={t('auth.requestAccess.title', 'Request access')}
        description={t(
          'auth.requestAccess.description',
          'Tell us about your organization. An administrator reviews every request.'
        )}
      />
      <form method="post" onSubmit={onSubmit} className="flex flex-col gap-3.5" noValidate>
        <div className="flex flex-col gap-1.5">
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
        <div className="flex flex-col gap-1.5">
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
        <div className="flex flex-col gap-1.5">
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
          <EntryBanner tone="danger" role="alert">
            {error}
          </EntryBanner>
        )}
        <EntryActions>
          <Button variant="signal" type="submit" disabled={!valid || isPending}>
            {isPending && <Loader2 aria-hidden className="size-4 animate-spin" />}
            {t('auth.requestAccess.submit', 'Send request')}
          </Button>
          <EntryBackLink />
        </EntryActions>
      </form>
    </EntryCard>
  )
}
