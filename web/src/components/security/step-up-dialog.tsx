'use client'

/**
 * The one dialog that asks a signed-in person to prove it is them before a
 * sensitive action: the app's step-up prompt, an owner approving their own
 * request, the console's step-up and four-eyes confirmations. Every caller
 * gets the same title, explanation, code field, alternatives (a recovery code,
 * a security key or passkey), lockout message and buttons.
 *
 * The dialog only collects the proof. `onSubmit` sends it; a thrown error is
 * shown in the dialog, the code is cleared (a used code cannot be replayed)
 * and the field is focused for the next one. The server decides; nothing here
 * is trusted by it.
 */

import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { KeyRound, Loader2, ShieldCheck } from 'lucide-react'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { PasswordInput } from '@/components/password-input'
import { useTranslation } from '@/context/i18n-provider'

import { TOTP_CODE_LENGTH, VerificationCodeInput } from './verification-code-input'

type Translate = ReturnType<typeof useTranslation>['t']

/** What the person presented. */
export type StepUpProofInput =
  | { kind: 'totp'; code: string }
  | { kind: 'recovery'; code: string }
  | { kind: 'password'; password: string }

/** A security key or passkey the person may confirm with instead of a code. */
export interface StepUpPasskeyOption {
  /** Runs the WebAuthn ceremony; throws when it fails or is cancelled. */
  onUse: () => Promise<void>
  /** Offer the key first (the person has one this browser can use). */
  preferred?: boolean
  /** Only a key is accepted for this action. */
  required?: boolean
  /** Say that only a key is accepted (default true when `required`). */
  explainRequired?: boolean
  /** This browser can use security keys. */
  supported: boolean
  /** The message for a failed ceremony. */
  errorMessage?: (err: unknown) => string
}

export interface StepUpDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Default: "Confirm it is you". */
  title?: string
  /** Why the action needs the proof. */
  description?: ReactNode
  /** How long the confirmation lasts, e.g. "You will not be asked again for 10 minutes." */
  rememberNote?: string
  /** What the account presents: an authenticator code (default) or its password. */
  factor?: 'totp' | 'password'
  /** Label of the code field. Default: "Code from your authenticator app". */
  codeLabel?: string
  /** Fields shown above the code (a reason, a summary). */
  children?: ReactNode
  /** The fields in `children` are valid (default true). */
  ready?: boolean
  /** Submit as soon as the code is complete and `ready` (default true). */
  autoSubmit?: boolean
  /** Default: "Confirm". */
  submitLabel?: string
  /** Icon in the submit button; default a shield. */
  submitIcon?: ReactNode
  destructive?: boolean
  /** Sends the proof. Throw to show an error and ask again. */
  onSubmit: (proof: StepUpProofInput) => Promise<void> | void
  /** The message for a refused proof; default handles rate limits and lockouts. */
  errorMessage?: (err: unknown, proof: StepUpProofInput) => string
  /** A message from outside the dialog (the previous code was refused). */
  problem?: string | null
  /** Offer "Use a recovery code" with this format. */
  recovery?: { length: number; groups?: number[] }
  /** Offer a security key or passkey. */
  passkey?: StepUpPasskeyOption
  /** How the person can confirm is still loading. */
  loading?: boolean
  /** Replaces the form: a state where no code can be entered (sign in again, load failure). */
  notice?: { body: ReactNode; actions: ReactNode }
}

/**
 * Default message for a refused proof: too many attempts and a locked account
 * get their own message; otherwise the server's message, else a generic one.
 */
export function stepUpProofErrorMessage(t: Translate, err: unknown): string {
  const e = (err ?? {}) as { statusCode?: unknown; status?: unknown; message?: unknown }
  const status =
    typeof e.statusCode === 'number' ? e.statusCode : typeof e.status === 'number' ? e.status : 0
  const message = typeof e.message === 'string' ? e.message : ''
  if (status === 429) {
    return t('components.stepUp.tooMany', 'Too many attempts. Wait a minute and try again.')
  }
  if (status === 403 && /locked/i.test(message)) {
    return t(
      'components.stepUp.locked',
      'Your account is locked after too many failed attempts. Try again later.'
    )
  }
  return message || t('components.stepUp.failed', 'Could not confirm your identity. Try again.')
}

type Mode = 'code' | 'recovery' | 'key'

export function StepUpDialog({
  open,
  onOpenChange,
  title,
  description,
  rememberNote,
  factor = 'totp',
  codeLabel,
  children,
  ready = true,
  autoSubmit = true,
  submitLabel,
  submitIcon,
  destructive,
  onSubmit,
  errorMessage,
  problem,
  recovery,
  passkey,
  loading,
  notice,
}: StepUpDialogProps) {
  const { t } = useTranslation()
  const [chosen, setChosen] = useState<Mode | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // Each opening starts clean.
  useEffect(() => {
    if (open) {
      setChosen(null)
      setCode('')
      setPassword('')
      setError(null)
      setBusy(false)
    }
  }, [open])

  const mode: Mode = passkey?.required
    ? 'key'
    : (chosen ?? (problem ? 'code' : passkey?.preferred ? 'key' : 'code'))
  const keyOffered = !!passkey && (passkey.preferred || passkey.required)

  const proofFor = (value: string): StepUpProofInput | null => {
    if (mode === 'key') return null
    if (factor === 'password' && mode === 'code') {
      return password ? { kind: 'password', password } : null
    }
    if (mode === 'recovery') {
      return recovery && value.length === recovery.length ? { kind: 'recovery', code: value } : null
    }
    return value.length === TOTP_CODE_LENGTH ? { kind: 'totp', code: value } : null
  }

  const send = async (proof: StepUpProofInput | null) => {
    if (!proof || busy || !ready) return
    setBusy(true)
    setError(null)
    try {
      await onSubmit(proof)
    } catch (err) {
      setError(errorMessage ? errorMessage(err, proof) : stepUpProofErrorMessage(t, err))
      setCode('')
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  const confirmWithKey = async () => {
    if (!passkey || busy) return
    setBusy(true)
    setError(null)
    try {
      await passkey.onUse()
    } catch (err) {
      setError(passkey.errorMessage ? passkey.errorMessage(err) : stepUpProofErrorMessage(t, err))
    } finally {
      setBusy(false)
    }
  }

  const switchTo = (next: Mode) => {
    setChosen(next)
    setCode('')
    setError(null)
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    void send(proofFor(code))
  }

  const shownError = error ?? problem ?? null
  const canSubmit = !busy && ready && !!proofFor(code)

  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent size={children ? 'md' : 'sm'}>
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldCheck className="size-5" aria-hidden />
              {title ?? t('components.stepUp.title', 'Confirm it is you')}
            </DialogTitle>
            {(description || rememberNote) && (
              <DialogDescription>
                {description}
                {description && rememberNote ? ' ' : null}
                {rememberNote}
              </DialogDescription>
            )}
          </DialogHeader>

          {notice ? (
            <>
              <DialogBody className="space-y-3">{notice.body}</DialogBody>
              <DialogFooter>{notice.actions}</DialogFooter>
            </>
          ) : loading ? (
            <DialogBody className="flex justify-center py-4" role="status" aria-busy="true">
              <Loader2 className="text-muted-foreground size-5 animate-spin" aria-hidden />
              <span className="sr-only">{t('components.stepUp.loading', 'Loading')}</span>
            </DialogBody>
          ) : (
            <>
              <DialogBody className="space-y-4">
                {children}

                {mode === 'key' && passkey && (
                  <div className="space-y-3">
                    {passkey.required && passkey.explainRequired !== false && (
                      <p className="text-muted-foreground text-sm">
                        {t(
                          'components.stepUp.keyRequired',
                          'A security key is required for this: the authenticator app is not accepted.'
                        )}
                      </p>
                    )}
                    {!passkey.supported && (
                      <Alert variant="destructive">
                        <AlertDescription>
                          {t(
                            'components.stepUp.keyUnsupported',
                            'This browser cannot use security keys or passkeys. Use a current browser.'
                          )}
                        </AlertDescription>
                      </Alert>
                    )}
                    <Button
                      type="button"
                      className="w-full"
                      onClick={() => void confirmWithKey()}
                      disabled={busy || !passkey.supported}
                      autoFocus
                    >
                      {busy ? (
                        <Loader2 className="me-2 size-4 animate-spin" aria-hidden />
                      ) : (
                        <KeyRound className="me-2 size-4" aria-hidden />
                      )}
                      {t('components.stepUp.useKey', 'Use security key or passkey')}
                    </Button>
                    {shownError && (
                      <p role="alert" className="text-destructive text-sm">
                        {shownError}
                      </p>
                    )}
                  </div>
                )}

                {mode !== 'key' && factor === 'password' && mode === 'code' && (
                  <div className="space-y-2">
                    <Label htmlFor="step-up-password">
                      {t('components.stepUp.password', 'Password')}
                    </Label>
                    <PasswordInput
                      id="step-up-password"
                      autoFocus
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={busy}
                      aria-invalid={shownError ? true : undefined}
                      aria-describedby={shownError ? 'step-up-password-error' : undefined}
                    />
                    {shownError && (
                      <p
                        id="step-up-password-error"
                        role="alert"
                        className="text-destructive text-sm"
                      >
                        {shownError}
                      </p>
                    )}
                  </div>
                )}

                {mode !== 'key' && !(factor === 'password' && mode === 'code') && (
                  <VerificationCodeInput
                    key={mode}
                    label={mode === 'recovery' ? undefined : codeLabel}
                    mode={mode === 'recovery' ? 'alphanumeric' : 'numeric'}
                    length={mode === 'recovery' && recovery ? recovery.length : TOTP_CODE_LENGTH}
                    groups={mode === 'recovery' ? recovery?.groups : undefined}
                    value={code}
                    onChange={setCode}
                    onComplete={(c) => {
                      if (autoSubmit) void send(proofFor(c))
                    }}
                    hint={
                      mode === 'recovery'
                        ? t(
                            'components.verificationCode.recoveryHint',
                            'One of the recovery codes you saved. Each code works once.'
                          )
                        : undefined
                    }
                    error={shownError}
                    disabled={busy}
                    autoFocus={!children}
                  />
                )}

                {mode !== 'key' && (recovery || keyOffered) && (
                  <div className="flex flex-col items-start gap-1">
                    {recovery && factor === 'totp' && (
                      <Button
                        type="button"
                        variant="link"
                        size="sm"
                        className="h-auto px-0"
                        onClick={() => switchTo(mode === 'recovery' ? 'code' : 'recovery')}
                      >
                        {mode === 'recovery'
                          ? t('components.stepUp.useApp', 'Use your authenticator app instead')
                          : t('components.stepUp.useRecovery', 'Use a recovery code instead')}
                      </Button>
                    )}
                    {keyOffered && (
                      <Button
                        type="button"
                        variant="link"
                        size="sm"
                        className="h-auto px-0"
                        onClick={() => switchTo('key')}
                      >
                        {t(
                          'components.stepUp.useKeyInstead',
                          'Use your security key or passkey instead'
                        )}
                      </Button>
                    )}
                  </div>
                )}

                {mode === 'key' && !passkey?.required && (
                  <Button
                    type="button"
                    variant="link"
                    size="sm"
                    className="h-auto px-0"
                    onClick={() => switchTo('code')}
                  >
                    {t(
                      'components.stepUp.useCode',
                      'Use a code from your authenticator app instead'
                    )}
                  </Button>
                )}
              </DialogBody>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => onOpenChange(false)}
                  disabled={busy}
                >
                  {t('components.stepUp.cancel', 'Cancel')}
                </Button>
                {mode !== 'key' && (
                  <Button
                    type="submit"
                    variant={destructive ? 'destructive' : 'default'}
                    disabled={!canSubmit}
                  >
                    {busy ? (
                      <Loader2 className="me-2 size-4 animate-spin" aria-hidden />
                    ) : (
                      (submitIcon ?? <ShieldCheck className="me-2 size-4" aria-hidden />)
                    )}
                    {submitLabel ?? t('components.stepUp.confirm', 'Confirm')}
                  </Button>
                )}
              </DialogFooter>
            </>
          )}
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
