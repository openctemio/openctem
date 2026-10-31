'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
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

import { useReplaceTwoFactor } from '../api/use-security'

interface ReplaceAuthenticatorDialogProps {
  open: boolean
  email?: string
  onClose: () => void
  /** The new authenticator is the only one: every other session was signed out. */
  onReplaced: () => void
}

/**
 * Moves two-factor authentication to a new authenticator app without turning
 * it off: the password and a current code (or a recovery code, for a lost
 * phone) start it, a code from the new app finishes it. The old app works
 * until then.
 */
export function ReplaceAuthenticatorDialog({
  open,
  email,
  onClose,
  onReplaced,
}: ReplaceAuthenticatorDialogProps) {
  const { t } = useTranslation()
  const passwordId = useId()
  const savedId = useId()
  const { startReplace, confirmReplace, isConfirming } = useReplaceTwoFactor()
  const [password, setPassword] = useState('')
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [codes, setCodes] = useState<string[] | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (!open) return
    setPassword('')
    setSetup(null)
    setCode('')
    setError(null)
    setCodes(null)
    setSaved(false)
  }, [open])

  async function confirm(value: string) {
    if (!setup || value.length !== TOTP_CODE_LENGTH || isConfirming) return
    setError(null)
    try {
      setCodes(await confirmReplace(value))
      onReplaced()
      toast.success(
        t('settings.twoFactor.replaced', 'New authenticator in use. Other sessions signed out.')
      )
    } catch (err) {
      setError(
        getErrorMessage(err, t('settings.twoFactor.invalidCode', 'Invalid verification code'))
      )
      setCode('')
    }
  }

  // Step 1: prove the account (password + current or recovery code).
  if (!setup) {
    return (
      <StepUpDialog
        open={open}
        onOpenChange={(o) => !o && onClose()}
        title={t('settings.twoFactor.replaceTitle', 'Replace authenticator')}
        description={t(
          'settings.twoFactor.replaceBody',
          'Lost your phone? Use a recovery code. The current app works until the new one is set up.'
        )}
        recovery={{
          length: ACCOUNT_RECOVERY_CODE.length,
          groups: [...ACCOUNT_RECOVERY_CODE.groups],
        }}
        ready={!!password}
        submitLabel={t('settings.twoFactor.continue', 'Continue')}
        onSubmit={async (proof) => {
          if (proof.kind === 'password') return
          const res = await startReplace({ password, code: proof.code })
          setSetup({ secret: res.secret, uri: res.otpauth_uri })
        }}
        errorMessage={(err) =>
          getErrorMessage(
            err,
            t('settings.twoFactor.replaceFailed', 'Could not start replacing the authenticator')
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
                  'settings.twoFactor.replacedCodesBody',
                  'Your old app and old recovery codes no longer work. Other sessions were signed out.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody className="grid gap-4">
              <RecoveryCodesPanel codes={codes} accountLabel={email} />
              <div className="flex items-center gap-2">
                <Checkbox
                  id={savedId}
                  checked={saved}
                  onCheckedChange={(v) => setSaved(v === true)}
                />
                <Label htmlFor={savedId} className="font-normal">
                  {t('settings.twoFactor.codesSaved', 'I have saved my recovery codes')}
                </Label>
              </div>
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
              void confirm(code)
            }}
          >
            <DialogHeader>
              <DialogTitle>
                {t('settings.twoFactor.replaceScanTitle', 'Scan with the new app')}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'settings.twoFactor.replaceScanBody',
                  'Then enter the 6-digit code it shows within 15 minutes.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody className="space-y-4">
              <div className="flex flex-col items-center gap-3">
                <TotpQrCode uri={setup.uri} size={176} />
                <SecretKey secret={setup.secret} />
              </div>
              <VerificationCodeInput
                label={t('settings.twoFactor.newCodeLabel', 'Code from the new app')}
                value={code}
                onChange={setCode}
                onComplete={(value) => void confirm(value)}
                disabled={isConfirming}
                error={error}
              />
            </DialogBody>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                {t('settings.twoFactor.cancel', 'Cancel')}
              </Button>
              <Button type="submit" disabled={code.length !== TOTP_CODE_LENGTH || isConfirming}>
                {isConfirming && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
                {t('settings.twoFactor.confirmNew', 'Use this app')}
              </Button>
            </DialogFooter>
          </DialogForm>
        )}
      </DialogContent>
    </Dialog>
  )
}
