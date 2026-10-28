'use client'

import { useState, type FormEvent } from 'react'
import { Loader2, Mail } from 'lucide-react'

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
}

/**
 * "Send the verification link again". The API answers 202 with the same body
 * for every address, so the message never says whether the address has an
 * account. On a server that cannot send email the person is told to ask an
 * administrator instead.
 */
export function ResendVerification({ email: knownEmail }: ResendVerificationProps) {
  const { t } = useTranslation()
  const emailUnavailable = useEmailUnavailable()
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState(false)
  const email = (knownEmail ?? typed).trim()

  if (emailUnavailable) {
    return (
      <p className="text-muted-foreground text-sm" role="note">
        {t(
          'auth.verifyEmail.noEmail',
          'This server cannot send email. Ask your administrator to verify your address.'
        )}
      </p>
    )
  }

  if (done) {
    return (
      <p className="text-sm" role="status">
        {t(
          'auth.verifyEmail.resendDone',
          'If this address has an account that is not verified yet, a new link is on its way.'
        )}
      </p>
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
    <form onSubmit={submit} className="grid w-full gap-2 text-start">
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
      <Button type="submit" variant="outline" disabled={busy || !email}>
        {busy ? <Loader2 className="size-4 animate-spin" /> : <Mail className="size-4" />}
        {t('auth.verifyEmail.resendSubmit', 'Send a new verification link')}
      </Button>
      {error && (
        <p className="text-destructive text-sm" role="alert">
          {t('auth.verifyEmail.resendFailed', 'Could not send the link. Try again in a minute.')}
        </p>
      )}
    </form>
  )
}
