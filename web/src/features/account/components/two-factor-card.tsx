'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { Clock, KeyRound, Loader2, RefreshCw, Smartphone } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { SignalChip } from '@/components/ui/signal-chip'
import { StatusLozenge } from '@/components/ui/status-lozenge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
  DialogForm,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { PasswordInput } from '@/components/password-input'
import { Skeleton } from '@/components/ui/skeleton'
import {
  ACCOUNT_RECOVERY_CODE,
  RecoveryCodesPanel,
  SecretKey,
  StepUpDialog,
  TOTP_CODE_LENGTH,
  TotpQrCode,
  VerificationCodeInput,
} from '@/components/security'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'

import {
  useDisableTwoFactor,
  useEnableTwoFactor,
  useRegenerateRecoveryCodes,
  useSetupTwoFactor,
  useTwoFactorStatus,
} from '../api/use-security'
import type { TwoFactorStatus } from '../types/account.types'
import { ReplaceAuthenticatorDialog } from './replace-authenticator-dialog'

interface TwoFactorCardProps {
  email?: string
  /**
   * Called after 2FA is turned on, turned off or moved to a new authenticator:
   * the server signed out every other session each time.
   */
  onOtherSessionsSignedOut?: () => void
}

type DialogKind = 'enable' | 'disable' | 'regenerate' | 'replace' | null

/** "Required by Acme and the platform", or null when nobody requires 2FA. */
function useRequiredByLabel(status?: TwoFactorStatus): string | null {
  const { t } = useTranslation()
  if (!status) return null
  const orgs = status.required_by?.organizations ?? []
  const platform = !!status.required_by?.platform
  if (orgs.length > 0 && platform) {
    return t(
      'settings.twoFactor.requiredByOrgsAndPlatform',
      'Required by {orgs} and the platform',
      {
        orgs: orgs.join(', '),
      }
    )
  }
  if (orgs.length > 0) {
    return t('settings.twoFactor.requiredByOrgs', 'Required by {orgs}', { orgs: orgs.join(', ') })
  }
  if (platform) return t('settings.twoFactor.requiredByPlatform', 'Required by the platform')
  if (status.required_by_organization) {
    return t('settings.twoFactor.required', 'Required by your organization')
  }
  return null
}

/**
 * Two-factor authentication section of My account -> Security.
 */
export function TwoFactorCard({ email, onOtherSessionsSignedOut }: TwoFactorCardProps) {
  const { t } = useTranslation()
  const { status, isLoading, mutate } = useTwoFactorStatus()
  const [dialog, setDialog] = useState<DialogKind>(null)

  const lowOnCodes = !!status?.enabled && status.recovery_codes_remaining <= 3
  const requiredBy = useRequiredByLabel(status)
  // Older servers do not send can_turn_off: the API still refuses when required.
  const canTurnOff = status?.can_turn_off !== false
  // While in grace only (not enforced yet), the due-date chip says it instead.
  const showRequiredBadge =
    !!requiredBy && (status?.enabled || status?.required_by_organization || !status?.grace_due_at)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Smartphone className="h-5 w-5" aria-hidden />
          {t('settings.twoFactor.title', 'Two-factor authentication')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.twoFactor.description',
            'Ask for a code from an authenticator app every time you sign in with your password.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading || !status ? (
          <Skeleton className="h-16 w-full" />
        ) : !status.supported ? (
          <p className="text-sm text-muted-foreground">
            {t(
              'settings.twoFactor.federated',
              "You sign in through your organization's identity provider, which handles two-factor authentication."
            )}
          </p>
        ) : (
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">
                  {status.enabled
                    ? t('settings.twoFactor.on', 'On')
                    : t('settings.twoFactor.off', 'Off')}
                </span>
                {status.enabled ? (
                  <StatusLozenge
                    tone="resolved"
                    label={t('settings.twoFactor.protected', 'Protected')}
                  />
                ) : null}
                {showRequiredBadge && <Badge variant="outline">{requiredBy}</Badge>}
                {!status.enabled && !status.required_by_organization && status.grace_due_at && (
                  <SignalChip icon={Clock} tone="alert">
                    {t('settings.twoFactor.dueBy', 'Required from {date}', {
                      date: formatDateSafe(status.grace_due_at),
                    })}
                  </SignalChip>
                )}
              </div>
              <p className="text-sm text-muted-foreground">
                {status.enabled
                  ? t('settings.twoFactor.turnedOnAt', 'Turned on {date}.', {
                      date: formatDateSafe(status.enabled_at),
                    })
                  : t(
                      'settings.twoFactor.passwordOnly',
                      'Anyone with your password can sign in.'
                    )}{' '}
                {status.enabled && (
                  <span className={lowOnCodes ? 'text-warning' : undefined}>
                    {status.recovery_codes_remaining === 1
                      ? t('settings.twoFactor.codesLeftOne', '1 recovery code left.')
                      : t('settings.twoFactor.codesLeft', '{count} recovery codes left.', {
                          count: status.recovery_codes_remaining,
                        })}
                  </span>
                )}
              </p>
              {status.enabled && !canTurnOff && (
                <p className="text-sm text-muted-foreground">
                  {t(
                    'settings.twoFactor.staysOn',
                    'It stays on while required. New phone? Replace the authenticator.'
                  )}
                </p>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              {status.enabled ? (
                <>
                  <Button variant="outline" size="sm" onClick={() => setDialog('replace')}>
                    <RefreshCw className="h-4 w-4" aria-hidden />
                    {t('settings.twoFactor.replace', 'Replace authenticator')}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setDialog('regenerate')}>
                    <KeyRound className="h-4 w-4" aria-hidden />
                    {t('settings.twoFactor.newCodes', 'New recovery codes')}
                  </Button>
                  {canTurnOff && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-destructive hover:text-destructive"
                      onClick={() => setDialog('disable')}
                    >
                      {t('settings.twoFactor.turnOff', 'Turn off')}
                    </Button>
                  )}
                </>
              ) : (
                <Button size="sm" onClick={() => setDialog('enable')}>
                  {t('settings.twoFactor.setUp', 'Set up')}
                </Button>
              )}
            </div>
          </div>
        )}
      </CardContent>

      <EnableTwoFactorDialog
        open={dialog === 'enable'}
        email={email}
        onClose={() => {
          setDialog(null)
          mutate()
        }}
        onEnabled={() => {
          mutate()
          onOtherSessionsSignedOut?.()
        }}
      />
      <DisableTwoFactorDialog
        open={dialog === 'disable'}
        onClose={() => setDialog(null)}
        onDisabled={() => {
          setDialog(null)
          mutate()
          onOtherSessionsSignedOut?.()
        }}
      />
      <ReplaceAuthenticatorDialog
        open={dialog === 'replace'}
        email={email}
        onClose={() => {
          setDialog(null)
          mutate()
        }}
        onReplaced={() => {
          mutate()
          onOtherSessionsSignedOut?.()
        }}
      />
      <RegenerateCodesDialog
        open={dialog === 'regenerate'}
        email={email}
        onClose={() => {
          setDialog(null)
          mutate()
        }}
      />
    </Card>
  )
}

// ---------------------------------------------------------------------------

function SaveCodesConfirm({
  id,
  saved,
  onSavedChange,
}: {
  id: string
  saved: boolean
  onSavedChange: (saved: boolean) => void
}) {
  const { t } = useTranslation()
  return (
    <div className="flex items-center gap-2">
      <Checkbox id={id} checked={saved} onCheckedChange={(v) => onSavedChange(v === true)} />
      <Label htmlFor={id} className="font-normal">
        {t('settings.twoFactor.codesSaved', 'I have saved my recovery codes')}
      </Label>
    </div>
  )
}

function EnableTwoFactorDialog({
  open,
  email,
  onClose,
  onEnabled,
}: {
  open: boolean
  email?: string
  onClose: () => void
  onEnabled: () => void
}) {
  const { t } = useTranslation()
  const passwordId = useId()
  const savedId = useId()
  const { setupTwoFactor, isSettingUp } = useSetupTwoFactor()
  const { enableTwoFactor, isEnabling } = useEnableTwoFactor()
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [codes, setCodes] = useState<string[] | null>(null)
  const [saved, setSaved] = useState(false)
  // Read through a ref so the start-once effect below does not depend on t.
  const startFailedRef = useRef(
    t('settings.twoFactor.startFailed', 'Could not start two-factor setup')
  )

  // A setup call issues a new secret and replaces the previous one: call it
  // once per opening (React StrictMode runs effects twice in development).
  const requested = useRef(false)
  useEffect(() => {
    if (!open) {
      requested.current = false
      return
    }
    if (requested.current) return
    requested.current = true
    setSetup(null)
    setPassword('')
    setCode('')
    setError(null)
    setCodes(null)
    setSaved(false)
    setupTwoFactor()
      .then((res) => setSetup({ secret: res.secret, uri: res.otpauth_uri }))
      .catch((err) => setError(getErrorMessage(err, startFailedRef.current)))
  }, [open, setupTwoFactor])

  async function send(value: string) {
    if (!setup || !password || value.length !== TOTP_CODE_LENGTH || isEnabling) return
    setError(null)
    try {
      const recovery = await enableTwoFactor({ password, code: value })
      setCodes(recovery)
      onEnabled()
      toast.success(t('settings.twoFactor.enabled', 'Two-factor authentication is on'))
    } catch (err) {
      setError(
        getErrorMessage(err, t('settings.twoFactor.invalidCode', 'Invalid verification code'))
      )
      setCode('')
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        // Once codes are shown, only the explicit "Done" closes the dialog.
        if (!o && (!codes || saved)) onClose()
      }}
    >
      <DialogContent>
        {codes ? (
          <>
            <DialogHeader>
              <DialogTitle>
                {t('settings.twoFactor.saveCodesTitle', 'Save your recovery codes')}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'settings.twoFactor.saveCodesBody',
                  'Two-factor authentication is on, and your other sessions were signed out. Use a recovery code to sign in if you lose your authenticator.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody className="grid gap-4">
              <RecoveryCodesPanel codes={codes} accountLabel={email} />
              <SaveCodesConfirm id={savedId} saved={saved} onSavedChange={setSaved} />
            </DialogBody>
            <DialogFooter>
              <Button disabled={!saved} onClick={onClose}>
                {t('settings.twoFactor.done', 'Done')}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <DialogForm
            onSubmit={(e) => {
              e.preventDefault()
              void send(code)
            }}
          >
            <DialogHeader>
              <DialogTitle>
                {t('settings.twoFactor.setUpTitle', 'Set up two-factor authentication')}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'settings.twoFactor.setUpBody',
                  'Scan the QR code with an authenticator app, then enter your current password and the 6-digit code it shows. Turning this on signs out your other sessions.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody className="space-y-4">
              <div className="flex flex-col items-center gap-3">
                {setup ? (
                  <>
                    <TotpQrCode uri={setup.uri} size={176} />
                    <SecretKey secret={setup.secret} />
                  </>
                ) : isSettingUp || !error ? (
                  <Skeleton className="h-44 w-44" />
                ) : null}
              </div>
              <div className="space-y-2">
                <Label htmlFor={passwordId}>
                  {t('settings.twoFactor.currentPassword', 'Current password')}
                </Label>
                <PasswordInput
                  id={passwordId}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={!setup || isEnabling}
                />
              </div>
              <VerificationCodeInput
                label={t('settings.twoFactor.codeLabel', 'Authentication code')}
                value={code}
                onChange={setCode}
                onComplete={(value) => void send(value)}
                disabled={!setup || isEnabling}
                error={error}
              />
            </DialogBody>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                {t('settings.twoFactor.cancel', 'Cancel')}
              </Button>
              <Button
                type="submit"
                disabled={!setup || !password || code.length !== TOTP_CODE_LENGTH || isEnabling}
              >
                {isEnabling && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
                {t('settings.twoFactor.turnOn', 'Turn on')}
              </Button>
            </DialogFooter>
          </DialogForm>
        )}
      </DialogContent>
    </Dialog>
  )
}

function DisableTwoFactorDialog({
  open,
  onClose,
  onDisabled,
}: {
  open: boolean
  onClose: () => void
  onDisabled: () => void
}) {
  const { t } = useTranslation()
  const passwordId = useId()
  const { disableTwoFactor } = useDisableTwoFactor()
  const [password, setPassword] = useState('')

  useEffect(() => {
    if (open) setPassword('')
  }, [open])

  return (
    <StepUpDialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={t('settings.twoFactor.turnOffTitle', 'Turn off two-factor authentication')}
      description={t(
        'settings.twoFactor.turnOffBody',
        'Sign-in will need only your password. Your other sessions are signed out and we email you.'
      )}
      recovery={{ length: ACCOUNT_RECOVERY_CODE.length, groups: [...ACCOUNT_RECOVERY_CODE.groups] }}
      ready={!!password}
      destructive
      submitLabel={t('settings.twoFactor.turnOff', 'Turn off')}
      onSubmit={async (proof) => {
        if (proof.kind === 'password') return
        await disableTwoFactor({ password, code: proof.code })
        toast.success(
          t(
            'settings.twoFactor.disabled',
            'Two-factor authentication is off. Other sessions signed out.'
          )
        )
        onDisabled()
      }}
      errorMessage={(err) =>
        getErrorMessage(
          err,
          t('settings.twoFactor.disableFailed', 'Could not turn off two-factor authentication')
        )
      }
    >
      <div className="space-y-2">
        <Label htmlFor={passwordId}>
          {t('settings.twoFactor.currentPassword', 'Current password')}
        </Label>
        <PasswordInput
          id={passwordId}
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
    </StepUpDialog>
  )
}

function RegenerateCodesDialog({
  open,
  email,
  onClose,
}: {
  open: boolean
  email?: string
  onClose: () => void
}) {
  const { t } = useTranslation()
  const { regenerateRecoveryCodes } = useRegenerateRecoveryCodes()
  const [codes, setCodes] = useState<string[] | null>(null)

  useEffect(() => {
    if (open) setCodes(null)
  }, [open])

  if (codes) {
    return (
      <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('settings.twoFactor.newCodesTitle', 'New recovery codes')}</DialogTitle>
            <DialogDescription>
              {t('settings.twoFactor.newCodesBody', 'Your old recovery codes no longer work.')}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <RecoveryCodesPanel codes={codes} accountLabel={email} />
          </DialogBody>
          <DialogFooter>
            <Button onClick={onClose}>{t('settings.twoFactor.done', 'Done')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )
  }

  return (
    <StepUpDialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={t('settings.twoFactor.regenerateTitle', 'Generate new recovery codes')}
      description={t(
        'settings.twoFactor.regenerateBody',
        'This replaces all of your recovery codes. Enter a code from your authenticator app to confirm.'
      )}
      submitLabel={t('settings.twoFactor.generate', 'Generate')}
      onSubmit={async (proof) => {
        if (proof.kind !== 'totp') return
        setCodes(await regenerateRecoveryCodes(proof.code))
      }}
      errorMessage={(err) =>
        getErrorMessage(err, t('settings.twoFactor.invalidCode', 'Invalid verification code'))
      }
    />
  )
}
