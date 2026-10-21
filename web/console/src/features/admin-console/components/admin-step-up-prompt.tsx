'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { StepUpDialog } from '@/components/security'
import { useTranslation } from '@/context/i18n-provider'
import {
  setAdminStepUpPrompt,
  type AdminStepUpAnswer,
  type AdminStepUpRequest,
} from '@console/lib/admin-api/client'
import { adminStepUpWithKey, useConsoleFactors } from '../api/use-console-factors'
import { isWebAuthnSupported } from '../lib/webauthn'
import { securityKeyErrorMessage } from '../lib/security-key-errors'

/**
 * The console's one step-up dialog. A protected action (an administrator,
 * the platform identity provider, an organization's owner or sign-in trust)
 * is refused until the administrator confirms. A security key or passkey is
 * offered first when they have one: it opens this session's five-minute
 * step-up window and adminFetch retries the action without a code. The code
 * from the authenticator app stays as the fallback where the console allows
 * it. Mounted once by the console shell (and by the enrollment gate). The
 * dialog itself is the shared StepUpDialog.
 */
export function AdminStepUpPrompt() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [request, setRequest] = useState<AdminStepUpRequest | null>(null)
  const resolver = useRef<((answer: AdminStepUpAnswer | null) => void) | null>(null)
  const { data: factors, error: factorsError } = useConsoleFactors(open)

  useEffect(() => {
    setAdminStepUpPrompt(
      (req) =>
        new Promise<AdminStepUpAnswer | null>((resolve) => {
          // A second prompt while one is open cancels the first.
          resolver.current?.(null)
          resolver.current = resolve
          setRequest(req)
          setOpen(true)
        })
    )
    return () => {
      setAdminStepUpPrompt(null)
      resolver.current?.(null)
      resolver.current = null
    }
  }, [])

  const finish = useCallback((value: AdminStepUpAnswer | null) => {
    const resolve = resolver.current
    resolver.current = null
    setOpen(false)
    resolve?.(value)
  }, [])

  const factorsKnown = !!factors || !!factorsError
  const keyAvailable =
    !!factors?.webauthn_enabled &&
    (factors?.authenticators.length ?? 0) > 0 &&
    isWebAuthnSupported()
  const codeAllowed =
    !!request && !request.keyOnly && !request.formCode && (factors?.totp_allowed ?? true)

  // A form that carries its own code only needs the dialog for a key: an
  // administrator without one types the code in the form instead.
  useEffect(() => {
    if (open && request?.formCode && factorsKnown && !keyAvailable) finish(null)
  }, [open, request, factorsKnown, keyAvailable, finish])

  return (
    <StepUpDialog
      open={open}
      onOpenChange={(next) => !next && finish(null)}
      title={t('admin.stepUp.title', 'Confirm it is you')}
      description={t(
        'admin.stepUp.why',
        'This action changes who can sign in or what they may do.'
      )}
      rememberNote={t(
        'admin.stepUp.remember',
        'One confirmation covers the next five minutes of such actions.'
      )}
      loading={!request?.keyOnly && !request?.problem && !factorsKnown}
      problem={request?.problem ?? null}
      passkey={
        keyAvailable || !codeAllowed
          ? {
              onUse: async () => {
                await adminStepUpWithKey()
                finish({ kind: 'key' })
              },
              preferred: keyAvailable,
              required: !codeAllowed,
              explainRequired: !request?.formCode,
              supported: isWebAuthnSupported(),
              errorMessage: (err) => securityKeyErrorMessage(err, t),
            }
          : undefined
      }
      onSubmit={(proof) => {
        if (proof.kind === 'totp') finish({ kind: 'code', code: proof.code })
      }}
    />
  )
}
