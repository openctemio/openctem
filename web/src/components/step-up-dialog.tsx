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

import { Button } from '@/components/ui/button'
import { StepUpDialog, stepUpProofErrorMessage, type StepUpProofInput } from '@/components/security'
import { useTranslation } from '@/context/i18n-provider'
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

type Translate = ReturnType<typeof useTranslation>['t']

/** The message to show for a failed POST /auth/step-up. */
export function stepUpErrorMessage(
  t: Translate,
  err: unknown,
  method: StepUpMethod | null
): string {
  if (err instanceof ApiClientError) {
    if (err.code === STEP_UP_FAILED_CODE) {
      return method === 'totp'
        ? t(
            'components.stepUp.badCode',
            'That code is not valid or was already used. Enter the current code.'
          )
        : t('components.stepUp.badPassword', 'Incorrect password.')
    }
    if (err.statusCode === 400) {
      return method === 'totp'
        ? t('components.verificationCode.lengthHint', 'Enter the {length}-digit code.', {
            length: 6,
          })
        : t('components.stepUp.enterPassword', 'Enter your password.')
    }
    if (err.statusCode === 429 || (err.statusCode === 403 && /locked/i.test(err.message))) {
      return stepUpProofErrorMessage(t, err)
    }
  }
  return t('components.stepUp.failed', 'Could not confirm your identity. Try again.')
}

export function StepUpDialogHost() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [state, setState] = useState<StepUpState | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)
  const resolver = useRef<((ok: boolean) => void) | null>(null)

  const loadState = useCallback(() => {
    setLoadFailed(false)
    setState(null)
    get<StepUpState>(STEP_UP_ENDPOINT, { _skipStepUpRetry: true })
      .then((s) => setState(s))
      .catch(() => setLoadFailed(true))
  }, [])

  useEffect(
    () =>
      registerStepUpHandler(
        () =>
          new Promise<boolean>((resolve) => {
            resolver.current = resolve
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

  const method = state?.method ?? null

  const submit = async (proof: StepUpProofInput) => {
    const body: StepUpProof =
      proof.kind === 'password' ? { password: proof.password } : { totp: proof.code }
    try {
      await post(STEP_UP_ENDPOINT, body, { _skipStepUpRetry: true })
    } catch (err) {
      if (err instanceof ApiClientError && err.code === STEP_UP_UNAVAILABLE_CODE) {
        setState((s) => (s ? { ...s, method: 'fresh_sign_in' } : s))
        return
      }
      throw err
    }
    finish(true)
  }

  const minutes = Math.max(1, Math.round((state?.window_seconds ?? 600) / 60))

  const notice = loadFailed
    ? {
        body: (
          <p className="text-destructive text-sm" role="alert">
            {t('components.stepUp.loadFailed', 'Could not load how to confirm your identity.')}
          </p>
        ),
        actions: (
          <>
            <Button type="button" variant="outline" onClick={() => finish(false)}>
              {t('components.stepUp.cancel', 'Cancel')}
            </Button>
            <Button type="button" onClick={loadState}>
              {t('components.stepUp.retry', 'Retry')}
            </Button>
          </>
        ),
      }
    : method === 'fresh_sign_in'
      ? {
          body: (
            <p className="text-muted-foreground text-sm">
              {t(
                'components.stepUp.signInAgainBody',
                'Your account signs in through your identity provider. Sign in again to confirm it is you, then repeat the action.'
              )}
            </p>
          ),
          actions: (
            <>
              <Button type="button" variant="outline" onClick={() => finish(false)}>
                {t('components.stepUp.cancel', 'Cancel')}
              </Button>
              <Button
                type="button"
                onClick={() =>
                  endSessionAndSignIn(window.location.pathname + window.location.search, {
                    reauth: true,
                  })
                }
              >
                {t('components.stepUp.signInAgain', 'Sign in again')}
              </Button>
            </>
          ),
        }
      : undefined

  return (
    <StepUpDialog
      open={open}
      onOpenChange={(next) => !next && finish(false)}
      description={t(
        'components.stepUp.description',
        'This action changes how your organization is secured. Confirm your identity to continue.'
      )}
      rememberNote={t(
        'components.stepUp.remember',
        'You will not be asked again for {minutes} minutes.',
        { minutes }
      )}
      factor={method === 'password' ? 'password' : 'totp'}
      loading={!loadFailed && !method}
      notice={notice}
      onSubmit={submit}
      errorMessage={(err) => stepUpErrorMessage(t, err, method)}
    />
  )
}
