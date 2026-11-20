'use client'

import { useState, type FormEvent } from 'react'
import { Loader2, Mail } from 'lucide-react'

import { EntryBanner } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { post } from '@/lib/api/client'
import { authEndpoints } from '@/lib/api/endpoints'
import { useEmailUnavailable } from '../api/use-auth-providers'

interface ResendVerificationProps {
  /** Known address (the sign-in form). Without it the person types theirs. */
  email?: string
  /** The card's one main action (the failed verification page): teal, no icon. */
  primary?: boolean
}

/**
 * "Send the verification link again". The API answers 202 with the same body
 * for every address, so the message never says whether the address has an
 * account. On a server that cannot send email the person is told to ask an
 * administrator instead.
 */
export function ResendVerification({
  email: knownEmail,
  primary = false,
}: ResendVerificationProps) {
  const { t } = useTranslation()
  const emailUnavailable = useEmailUnavailable()
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState(false)
  const email = (knownEmail ?? typed).trim()

  if (emailUnavailable) {
    return (
      <EntryBanner tone="warn" role="note">
        {t(
          'auth.verifyEmail.noEmail',
          'This server cannot send email. Ask your administrator to verify your address.'
        )}
      </EntryBanner>
    )
  }

  if (done) {
    return (
      <EntryBanner tone="ok" role="status">
        {t(
          'auth.verifyEmail.resendDone',
          'If this address has an account that is not verified yet, a new link is on its way.'
        )}
      </EntryBanner>
    )
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (!email) return
    setBusy(true)
    setError(false)
    try {
      await post(authEndpoints.resendVerification(), { email })
      setDone(true)
    } catch {
      setError(true)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="flex w-full flex-col gap-2 text-start">
      {/* A refusal is one banner in the card, above the fields (entry rule). */}
      {error && (
        <EntryBanner tone="danger" role="alert">
          {t('auth.verifyEmail.resendFailed', 'Could not send the link. Try again in a minute.')}
        </EntryBanner>
      )}
      {knownEmail === undefined && (
        <>
          <Label htmlFor="resend-verification-email">
            {t('auth.verifyEmail.resendEmail', 'Email address')}
          </Label>
          <Input
            id="resend-verification-email"
            type="email"
            autoComplete="email"
            value={typed}
            disabled={busy}
            onChange={(e) => setTyped(e.target.value)}
          />
        </>
      )}
      <Button type="submit" variant={primary ? 'signal' : 'outline'} disabled={busy || !email}>
        {busy ? (
          <Loader2 aria-hidden className="size-4 animate-spin" />
        ) : (
          !primary && <Mail aria-hidden className="size-4" />
        )}
        {t('auth.verifyEmail.resendSubmit', 'Send a new verification link')}
      </Button>
    </form>
  )
}
