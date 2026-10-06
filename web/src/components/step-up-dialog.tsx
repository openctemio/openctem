/**
 * Step-up re-authentication dialog: the one place the app asks a signed-in
 * user to confirm their identity before a sensitive action.
 *
 * Mounted once (app providers). The API client calls it through
 * `requestStepUp()` when a request answers `403 STEP_UP_REQUIRED`, and retries
 * the request once after a successful `POST /api/v1/auth/step-up`.
 *
 * - `totp`: the account has an authenticator; ask for a current code.
 * - `password`: ask for the account password.
 * - `fresh_sign_in`: an SSO account without an authenticator; the only way to
 *   re-authenticate is to sign in again.
 */

'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Loader2, ShieldCheck } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { PasswordInput } from '@/components/password-input'
import { OneTimeCodeInput } from '@/components/security'
import { get, post } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'
import {
  registerStepUpHandler,
  STEP_UP_ENDPOINT,
  STEP_UP_FAILED_CODE,
  STEP_UP_UNAVAILABLE_CODE,
  type StepUpMethod,
  type StepUpProof,
  type StepUpState,
} from '@/lib/api/step-up'
import { endSessionAndSignIn } from '@/stores/auth-store'

/** The message to show for a failed POST /auth/step-up. */
export function stepUpErrorMessage(err: unknown, method: StepUpMethod | null): string {
  if (err instanceof ApiClientError) {
    if (err.code === STEP_UP_FAILED_CODE) {
      return method === 'totp'
        ? 'That code is not valid or was already used. Enter the current code.'
        : 'Incorrect password.'
    }
    if (err.statusCode === 429) return 'Too many attempts. Wait a minute and try again.'
    if (err.statusCode === 400) {
      return method === 'totp' ? 'Enter the 6-digit code.' : 'Enter your password.'
    }
    if (err.statusCode === 403 && /locked/i.test(err.message)) {
      return 'Your account is locked after too many failed attempts. Try again later.'
    }
  }
  return 'Could not confirm your identity. Try again.'
}

export function StepUpDialogHost() {
  const [open, setOpen] = useState(false)
  const [method, setMethod] = useState<StepUpMethod | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const resolver = useRef<((ok: boolean) => void) | null>(null)

  const loadState = useCallback(() => {
    setLoadFailed(false)
    setMethod(null)
    get<StepUpState>(STEP_UP_ENDPOINT, { _skipStepUpRetry: true })
      .then((s) => setMethod(s.method))
      .catch(() => setLoadFailed(true))
  }, [])

  useEffect(
    () =>
      registerStepUpHandler(
        () =>
          new Promise<boolean>((resolve) => {
            resolver.current = resolve
            setValue('')
            setError(null)
            setSubmitting(false)
            setOpen(true)
            loadState()
          })
      ),
    [loadState]
  )

  const finish = useCallback((ok: boolean) => {
    resolver.current?.(ok)
    resolver.current = null
    setOpen(false)
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!method || method === 'fresh_sign_in' || submitting) return
    const proof: StepUpProof = method === 'totp' ? { totp: value } : { password: value }
    setSubmitting(true)
    setError(null)
    try {
      await post(STEP_UP_ENDPOINT, proof, { _skipStepUpRetry: true })
      finish(true)
    } catch (err) {
      if (err instanceof ApiClientError && err.code === STEP_UP_UNAVAILABLE_CODE) {
        setMethod('fresh_sign_in')
      } else {
        setError(stepUpErrorMessage(err, method))
      }
      setValue('')
    } finally {
      setSubmitting(false)
    }
  }

  const canSubmit =
    !submitting && (method === 'totp' ? value.length === 6 : method === 'password' && !!value)

  return (
    <Dialog open={open} onOpenChange={(next) => !next && finish(false)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" aria-hidden />
            Confirm it is you
          </DialogTitle>
          <DialogDescription>
            This action changes how your organization is secured. Confirm your identity to continue;
            you will not be asked again for 10 minutes.
          </DialogDescription>
        </DialogHeader>

        {loadFailed && (
          <div className="space-y-3">
            <p className="text-destructive text-sm" role="alert">
              Could not load how to confirm your identity.
            </p>
            <Button type="button" variant="outline" onClick={loadState}>
              Retry
            </Button>
          </div>
        )}

        {!loadFailed && !method && (
          <div className="flex justify-center py-4" aria-busy="true">
            <Loader2 className="text-muted-foreground h-5 w-5 animate-spin" aria-hidden />
          </div>
        )}

        {method === 'fresh_sign_in' && (
          <div className="space-y-4">
            <p className="text-muted-foreground text-sm">
              Your account signs in through your identity provider. Sign in again to confirm it is
              you, then repeat the action.
            </p>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => finish(false)}>
                Cancel
              </Button>
              <Button
                type="button"
                onClick={() =>
                  endSessionAndSignIn(window.location.pathname + window.location.search, {
                    reauth: true,
                  })
                }
              >
                Sign in again
              </Button>
            </DialogFooter>
          </div>
        )}

        {(method === 'totp' || method === 'password') && (
          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="step-up-proof">
                {method === 'totp' ? 'Authenticator code' : 'Password'}
              </Label>
              {method === 'totp' ? (
                <OneTimeCodeInput
                  id="step-up-proof"
                  autoFocus
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  disabled={submitting}
                  aria-invalid={!!error}
                  aria-describedby={error ? 'step-up-error' : undefined}
                />
              ) : (
                <PasswordInput
                  id="step-up-proof"
                  autoFocus
                  autoComplete="current-password"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  disabled={submitting}
                  aria-invalid={!!error}
                  aria-describedby={error ? 'step-up-error' : undefined}
                />
              )}
              {error && (
                <p id="step-up-error" className="text-destructive text-sm" role="alert">
                  {error}
                </p>
              )}
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => finish(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={!canSubmit}>
                {submitting && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
                Confirm
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
