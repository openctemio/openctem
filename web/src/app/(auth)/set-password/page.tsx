'use client'

import { useLinkToken } from '@/features/auth/lib/link-token'
import { PasswordTokenForm } from '@/features/auth/components/password-token-form'

/**
 * One-time setup link for an account an administrator created:
 * /set-password#token=... (public route — the user has no session yet).
 */
export default function SetPasswordPage() {
  const token = useLinkToken()
  if (token === null) return null
  return <PasswordTokenForm mode="setup" token={token} />
}
