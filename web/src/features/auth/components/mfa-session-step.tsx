/**
 * Second-factor step for a person who is already signed in (refresh-token
 * session) but whose session an organization's 2FA policy holds back: right
 * after accepting an invitation, or when a token refresh is refused.
 *
 * It asks the API for the enrollment (or verify) challenge, renders the same
 * MfaStep the login uses, and on completion mints the tenant token for the
 * organization the person was trying to open. Failures say what happened and
 * offer a retry; only a gone session sends the person to sign in.
 */

'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Loader2 } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

import {
  selectTenantAction,
  startSessionMfaAction,
  type LoginResult,
  type MfaPurpose,
} from '../actions/local-auth-actions'
import { MfaStep } from './mfa-step'

interface MfaSessionStepProps {
  /** The organization to open once the second factor is proven. */
  tenantId?: string
  /** The tenant token is minted; the caller navigates into the app. */
  onComplete: () => void
  /** The session itself is gone (401): the caller sends the person to sign in. */
  onSessionExpired: () => void
}

type Phase =
  | { kind: 'starting' }
  | { kind: 'step'; purpose: MfaPurpose; orgs?: string[] }
  | { kind: 'opening' }
  | { kind: 'error'; message: string }

export function MfaSessionStep({ tenantId, onComplete, onSessionExpired }: MfaSessionStepProps) {
  const { t } = useTranslation()
  const [phase, setPhase] = useState<Phase>({ kind: 'starting' })
  const [attempt, setAttempt] = useState(0)
  const expiredRef = useRef(onSessionExpired)
  useEffect(() => {
    expiredRef.current = onSessionExpired
  }, [onSessionExpired])

  // One challenge per attempt (React StrictMode runs effects twice in
  // development; a second start would replace the first challenge).
  const startedFor = useRef(-1)
  useEffect(() => {
    if (startedFor.current === attempt) return
    startedFor.current = attempt
    void startSessionMfaAction().then((res) => {
      if (res.sessionExpired) {
        expiredRef.current()
        return
      }
      if (res.success && res.purpose) {
        setPhase({ kind: 'step', purpose: res.purpose, orgs: res.orgs })
        return
      }
      setPhase({
        kind: 'error',
        message:
          res.error ||
          t('auth.mfaSession.startFailed', 'Could not start two-factor setup. Try again.'),
      })
    })
    // t only changes with the locale.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt])

  const retry = useCallback(() => {
    setPhase({ kind: 'starting' })
    setAttempt((n) => n + 1)
  }, [])

  const finish = useCallback(
    async (result: LoginResult) => {
      setPhase({ kind: 'opening' })
      // The second step signed the person in again with a session that proved
      // the factor; open the organization with it.
      let opened = result.success && !result.requiresTenantSelection
      let message = result.error
      if (!opened && tenantId) {
        const selected = await selectTenantAction(tenantId)
        opened = selected.success
        message = selected.error
      }
      if (opened) {
        onComplete()
        return
      }
      setPhase({
        kind: 'error',
        message:
          message ||
          t(
            'auth.mfaSession.openFailed',
            'Two-factor authentication is on, but the organization could not be opened. Try again.'
          ),
      })
    },
    // t only changes with the locale.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [tenantId, onComplete]
  )

  if (phase.kind === 'starting' || phase.kind === 'opening') {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
        <Loader2 className="h-4 w-4 animate-spin" />
        {phase.kind === 'starting'
          ? t('auth.mfaSession.starting', 'Preparing two-factor setup')
          : t('auth.mfaSession.opening', 'Opening your organization')}
      </div>
    )
  }

  if (phase.kind === 'error') {
    return (
      <Alert variant="destructive">
        <AlertTitle>
          {t('auth.mfaSession.errorTitle', 'Two-factor setup did not finish')}
        </AlertTitle>
        <AlertDescription className="grid gap-3">
          <span>{phase.message}</span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="justify-self-start"
            onClick={retry}
          >
            {t('auth.mfaSession.retry', 'Try again')}
          </Button>
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <MfaStep
      purpose={phase.purpose}
      orgs={phase.orgs}
      backLabel={t('auth.mfaSession.cancel', 'Cancel')}
      onDone={(result) => void finish(result)}
      onCancel={(message) =>
        setPhase({
          kind: 'error',
          message:
            message ||
            t(
              'auth.mfaSession.cancelled',
              'Two-factor setup was cancelled. You can start it again.'
            ),
        })
      }
    />
  )
}
