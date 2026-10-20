'use client'

import type { ReactNode } from 'react'
import { VerificationCodeInput } from '@/components/security'
import { useTranslation } from '@/context/i18n-provider'
import { useConsoleFactors } from '../api/use-console-factors'
import { isWebAuthnSupported } from '../lib/webauthn'

/**
 * Whether a form's authenticator-code field may stay empty: the signed-in
 * administrator holds a security key this browser can use. An empty code is
 * refused by the API with STEP_UP_REQUIRED, and the console's step-up dialog
 * then confirms with the key and retries the request inside the step-up
 * window (adminFetch). The API decides; this only shapes the form.
 */
export function useStepUpCodeOptional(): boolean {
  const { data } = useConsoleFactors()
  return !!data?.webauthn_enabled && (data.authenticators?.length ?? 0) > 0 && isWebAuthnSupported()
}

/** A form's step-up code is ready: six digits, or empty when a key can confirm. */
export function stepUpCodeReady(code: string, optional: boolean): boolean {
  const c = code.trim()
  return c.length >= 6 || (optional && c === '')
}

/**
 * A console form's step-up code: the shared verification-code field, which
 * may stay empty when the administrator's security key can confirm instead.
 */
export function StepUpCodeField({
  id,
  value,
  onChange,
  optional = false,
  error,
  hint,
}: {
  id?: string
  value: string
  onChange: (code: string) => void
  /** An empty code confirms with the security key (useStepUpCodeOptional). */
  optional?: boolean
  error?: string | null
  hint?: ReactNode
}) {
  const { t } = useTranslation()
  const keyHint = optional
    ? t(
        'admin.stepUp.codeOptional',
        'Or leave it empty to confirm with your security key or passkey.'
      )
    : null
  return (
    <VerificationCodeInput
      id={id}
      value={value}
      onChange={onChange}
      required={!optional}
      error={error}
      hint={
        keyHint && hint ? (
          <>
            {hint} {keyHint}
          </>
        ) : (
          (hint ?? keyHint)
        )
      }
    />
  )
}
