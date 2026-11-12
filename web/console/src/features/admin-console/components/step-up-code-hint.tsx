'use client'

import { useCallback, useEffect, useRef, useState, type ReactNode, type Ref } from 'react'
import { VerificationCodeInput } from '@/components/security'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
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
  inputRef,
}: {
  id?: string
  inputRef?: Ref<HTMLInputElement>
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
      label={t('components.verificationCode.label', 'Code from your authenticator app')}
      value={value}
      onChange={onChange}
      required={!optional}
      ref={inputRef}
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

/**
 * The state of a confirmation that asks for a reason and an authenticator
 * code: the one place it lives, so no form can forget to clear it.
 *
 * `open` is the confirmation's open flag. Everything is cleared whenever it
 * opens or closes (a one-time code and an old reason must never come back),
 * and `reset()` clears it after a submit. After a refused code call
 * `refuseCode(message)`: the code is used up, so it is cleared and the
 * message shown under the field.
 */
export function useReasonAndCode(open: boolean) {
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const codeOptional = useStepUpCodeOptional()

  const reset = useCallback(() => {
    setReason('')
    setCode('')
    setCodeError(null)
  }, [])
  useEffect(() => {
    reset()
  }, [open, reset])

  const refuseCode = useCallback((message: string) => {
    setCode('')
    setCodeError(message)
  }, [])

  return {
    reason,
    setReason,
    code,
    setCode,
    codeError,
    setCodeError,
    codeOptional,
    reset,
    refuseCode,
    /** A reason is typed (it is kept in the audit log). */
    reasonOk: reason.trim() !== '',
    /** The code is six digits, or empty when a security key can confirm. */
    codeOk: stepUpCodeReady(code, codeOptional),
  }
}

export type ReasonAndCode = ReturnType<typeof useReasonAndCode>

/**
 * The reason and code fields of a confirmation, bound to useReasonAndCode.
 * The reason is marked required and says why; on open the focus goes to the
 * first empty field. `withReason={false}` for a confirmation that needs the
 * code only.
 */
export function ReasonAndCodeFields({
  id,
  state,
  withReason = true,
  maxLength = 1000,
  codeHint,
  codeRequired = false,
}: {
  id: string
  state: ReasonAndCode
  withReason?: boolean
  maxLength?: number
  codeHint?: ReactNode
  /** Always ask for the code, even when a security key could confirm. */
  codeRequired?: boolean
}) {
  const { t } = useTranslation()
  const reasonRef = useRef<HTMLTextAreaElement>(null)
  const codeRef = useRef<HTMLInputElement>(null)
  const empty = useRef({ reason: !state.reason, code: !state.code })
  // The dialog moves focus itself right after it opens: ask for ours after it.
  useEffect(() => {
    const timer = setTimeout(() => {
      if (withReason && empty.current.reason) reasonRef.current?.focus()
      else if (empty.current.code) codeRef.current?.focus()
    }, 0)
    return () => clearTimeout(timer)
  }, [withReason])
  return (
    <div className="space-y-4">
      {withReason && (
        <div className="space-y-2">
          <Label
            htmlFor={`${id}-reason`}
            className="after:ms-0.5 after:text-destructive after:content-['*']"
          >
            {t('admin.reasonAndCode.reason', 'Reason')}
          </Label>
          <Textarea
            id={`${id}-reason`}
            ref={reasonRef}
            rows={2}
            maxLength={maxLength}
            value={state.reason}
            onChange={(e) => state.setReason(e.target.value)}
            required
            aria-describedby={`${id}-reason-hint`}
          />
          <p id={`${id}-reason-hint`} className="text-xs text-muted-foreground">
            {t(
              'admin.reasonAndCode.reasonHint',
              'Required: say why you make this change. It is kept in the audit log.'
            )}
          </p>
        </div>
      )}
      <StepUpCodeField
        id={`${id}-code`}
        inputRef={codeRef}
        value={state.code}
        onChange={(v) => {
          state.setCode(v)
          if (state.codeError) state.setCodeError(null)
        }}
        optional={state.codeOptional && !codeRequired}
        error={state.codeError}
        hint={codeHint}
      />
    </div>
  )
}
