'use client'

import { useLinkToken } from '@/features/auth/lib/link-token'
import { PasswordTokenForm } from '@/features/auth/components/password-token-form'

/** Forgot-password email link: /reset-password#token=... */
export default function ResetPasswordPage() {
  const token = useLinkToken()
  if (token === null) return null
  return <PasswordTokenForm mode="reset" token={token} />
}
