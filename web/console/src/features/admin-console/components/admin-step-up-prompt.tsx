'use client'

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import {
  setAdminStepUpPrompt,
  type AdminStepUpAnswer,
  type AdminStepUpRequest,
} from '@console/lib/admin-api/client'
import { adminStepUpWithKey, useConsoleFactors } from '../api/use-console-factors'
import { isWebAuthnSupported } from '../lib/webauthn'
import { securityKeyErrorMessage } from '../lib/security-key-errors'

type Mode = 'key' | 'code'

/**
 * The console's one step-up dialog. A protected action (an administrator,
 * the platform identity provider, an organization's owner or sign-in trust)
 * is refused until the administrator confirms. A security key or passkey is
 * offered first when they have one: it opens this session's five-minute
 * step-up window and adminFetch retries the action without a code. The code
 * from the authenticator app stays as the fallback where the console allows
 * it. Mounted once by the console shell (and by the enrollment gate).
 */
export function AdminStepUpPrompt() {
  const { t } = useTranslation()
  const codeId = useId()
  const [open, setOpen] = useState(false)
  const [request, setRequest] = useState<AdminStepUpRequest | null>(null)
  const [chosen, setChosen] = useState<Mode | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [keyError, setKeyError] = useState<string | null>(null)
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
          // A refused code is corrected with another code.
          setChosen(req.problem ? 'code' : null)
          setCode('')
          setKeyError(null)
          setBusy(false)
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
    setCode('')
    setBusy(false)
    resolve?.(value)
  }, [])

  const factorsKnown = !!factors || !!factorsError
  const keyAvailable =
    !!factors?.webauthn_enabled &&
    (factors?.authenticators.length ?? 0) > 0 &&
    isWebAuthnSupported()
  const codeAllowed =
    !!request && !request.keyOnly && !request.formCode && (factors?.totp_allowed ?? true)
  const mode: Mode | 'loading' = request?.keyOnly
    ? 'key'
    : (chosen ?? (!factorsKnown ? 'loading' : keyAvailable ? 'key' : 'code'))

  // A form that carries its own code only needs the dialog for a key: an
  // administrator without one types the code in the form instead.
  useEffect(() => {
    if (open && request?.formCode && factorsKnown && !keyAvailable) finish(null)
  }, [open, request, factorsKnown, keyAvailable, finish])

  const confirmWithKey = async () => {
    setBusy(true)
    setKeyError(null)
    try {
      await adminStepUpWithKey()
      finish({ kind: 'key' })
    } catch (err) {
      setKeyError(securityKeyErrorMessage(err, t))
      setBusy(false)
    }
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (mode === 'code' && /^\d{6}$/.test(code)) finish({ kind: 'code', code })
  }

  const description =
    mode === 'code'
      ? t(
          'admin.stepUp.description',
          'This action changes who can sign in or what they may do. Enter a fresh code from your authenticator. One code covers the next five minutes of such actions.'
        )
      : t(
          'admin.stepUp.keyDescription',
          'This action changes who can sign in or what they may do. Confirm with your security key or passkey. One confirmation covers the next five minutes of such actions.'
        )

  return (
    <Dialog open={open} onOpenChange={(next) => !next && finish(null)}>
      <DialogContent>
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldCheck className="size-5" />
              {t('admin.stepUp.title', 'Confirm it is you')}
            </DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            {mode === 'loading' && (
              <div className="flex justify-center py-4" role="status">
                <Loader2 className="size-5 animate-spin text-muted-foreground" />
                <span className="sr-only">{t('admin.stepUp.loading', 'Loading')}</span>
              </div>
            )}

            {mode === 'key' && (
              <div className="space-y-3">
                {request?.keyOnly && !request.formCode && (
                  <p className="text-sm text-muted-foreground">
                    {t(
                      'admin.stepUp.keyRequired',
                      'The console requires a security key for this: the authenticator app is not accepted.'
                    )}
                  </p>
                )}
                {!isWebAuthnSupported() && (
                  <Alert variant="destructive">
                    <AlertDescription>
                      {t(
                        'admin.keys.unsupported',
                        'This browser cannot use security keys or passkeys. Use a current browser.'
                      )}
                    </AlertDescription>
                  </Alert>
                )}
                <Button
                  type="button"
                  className="w-full"
                  onClick={() => void confirmWithKey()}
                  disabled={busy || !isWebAuthnSupported()}
                  autoFocus
                >
                  {busy ? (
                    <Loader2 className="me-2 size-4 animate-spin" />
                  ) : (
                    <KeyRound className="me-2 size-4" />
                  )}
                  {t('admin.keys.useKey', 'Use security key or passkey')}
                </Button>
                {keyError && (
                  <Alert variant="destructive">
                    <AlertDescription>{keyError}</AlertDescription>
                  </Alert>
                )}
                {codeAllowed && (
                  <Button
                    type="button"
                    variant="link"
                    className="h-auto px-0"
                    onClick={() => setChosen('code')}
                  >
                    {t('admin.stepUp.useCode', 'Use a code from your authenticator app instead')}
                  </Button>
                )}
              </div>
            )}

            {mode === 'code' && (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor={codeId}>
                    {t('admin.confirm.code', 'Code from your authenticator')}
                  </Label>
                  <Input
                    id={codeId}
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    className="w-36 font-mono tracking-widest"
                    autoFocus
                    required
                  />
                </div>
                {request?.problem && (
                  <Alert variant="destructive">
                    <AlertDescription>{request.problem}</AlertDescription>
                  </Alert>
                )}
                {keyAvailable && (
                  <Button
                    type="button"
                    variant="link"
                    className="h-auto px-0"
                    onClick={() => setChosen('key')}
                  >
                    {t('admin.stepUp.useKeyInstead', 'Use your security key or passkey instead')}
                  </Button>
                )}
              </>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => finish(null)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            {mode === 'code' && (
              <Button type="submit" disabled={!/^\d{6}$/.test(code)}>
                {t('admin.stepUp.confirm', 'Confirm')}
              </Button>
            )}
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
