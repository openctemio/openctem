'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { TonePill } from '@/features/shared/components/tone-pill'
import { saveCaptcha, verifyCaptchaSecret } from '../api/use-platform-settings'
import type { CaptchaSettings } from '../types'
import {
  LockedByEnvironment,
  ReasonConfirmDialog,
  SecretField,
  SettingChangedLine,
  handleSaveConflict,
  secretPatch,
} from './console-setting-parts'

export interface CaptchaSettingsFormProps {
  settings: CaptchaSettings
  canEdit: boolean
  onSaved: () => void
}

/**
 * Settings > CAPTCHA: the Cloudflare Turnstile keys that protect sign-up,
 * request access and every sign-in after repeated failures. The secret is
 * write-only. "Check the secret" asks Turnstile before or after saving. A
 * change applies at once on every server, needs a reason and is told to
 * every administrator.
 */
export function CaptchaSettingsForm({ settings, canEdit, onSaved }: CaptchaSettingsFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const locked = settings.locked_by_environment
  const editable = canEdit && !locked
  const [siteKey, setSiteKey] = useState(settings.site_key)
  const [secret, setSecret] = useState('')
  const [clearSecret, setClearSecret] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [checking, setChecking] = useState(false)

  useEffect(() => {
    setSiteKey(settings.site_key)
    setSecret('')
    setClearSecret(false)
  }, [settings])

  const dirty = siteKey.trim() !== settings.site_key || secret !== '' || clearSecret
  const turningOff = clearSecret && siteKey.trim() === ''

  const check = async () => {
    setChecking(true)
    try {
      const { result } = await verifyCaptchaSecret(secret.trim() || undefined)
      if (result === 'valid')
        toast.success(t('admin.captcha.checkValid', 'Turnstile accepts this secret key'))
      else if (result === 'invalid')
        toast.error(t('admin.captcha.checkInvalid', 'Turnstile does not know this secret key'))
      else
        toast.warning(
          t(
            'admin.captcha.checkUnreachable',
            'Turnstile could not be reached; nothing is known about the key'
          )
        )
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : t('admin.captcha.checkFailed', 'The check failed')
      )
    } finally {
      setChecking(false)
    }
  }

  const save = async (reason: string) => {
    try {
      await saveCaptcha({
        site_key: siteKey.trim(),
        secret: secretPatch(secret, clearSecret),
        reason,
        version: settings.version,
      })
      toast.success(t('admin.captcha.saved', 'CAPTCHA keys saved'))
      onSaved()
    } catch (e) {
      if (
        handleSaveConflict(
          e,
          onSaved,
          t(
            'admin.settings.conflict',
            'Another administrator changed this setting. The latest values are shown.'
          )
        )
      )
        return
      throw e
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle>{t('admin.captcha.title', 'CAPTCHA (Cloudflare Turnstile)')}</CardTitle>
            <TonePill
              tone={settings.secret_set ? 'success' : 'warning'}
              label={
                settings.secret_set ? t('admin.captcha.on', 'On') : t('admin.captcha.off', 'Off')
              }
            />
          </div>
          <CardDescription>
            {t(
              'admin.captcha.description',
              'Protects registration, the request-access form and every sign-in after repeated failures, for organizations and this console. Without keys only the rate limits apply.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {locked && <LockedByEnvironment envVar={settings.env_var} />}
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor={`${id}-site`}>
                {t('admin.captcha.siteKey', 'Site key (public)')}
              </Label>
              <Input
                id={`${id}-site`}
                value={siteKey}
                onChange={(e) => setSiteKey(e.target.value)}
                disabled={!editable}
                autoComplete="off"
                spellCheck={false}
                placeholder="0x4AAAAAAA..."
              />
            </div>
            <SecretField
              label={t('admin.captcha.secret', 'Secret key')}
              isSet={settings.secret_set}
              value={secret}
              onChange={setSecret}
              clear={clearSecret}
              onClear={setClearSecret}
              disabled={!editable}
              help={t(
                'admin.captcha.secretHelp',
                'Write-only: it is encrypted on the server and never shown again.'
              )}
            />
          </div>
          {clearSecret && siteKey.trim() !== '' && (
            <p className="text-sm text-destructive">
              {t(
                'admin.captcha.bothKeys',
                'Set both keys, or remove both: clear the site key too to turn the CAPTCHA off.'
              )}
            </p>
          )}
          <SettingChangedLine change={settings} />
          {canEdit && (
            <div className="flex flex-wrap items-center justify-end gap-3">
              <Button
                variant="outline"
                onClick={() => void check()}
                disabled={checking || (!settings.secret_set && secret.trim() === '')}
              >
                {checking && <Loader2 className="me-1.5 size-4 animate-spin" />}
                {t('admin.captcha.check', 'Check the secret key')}
              </Button>
              {!locked && (
                <Button onClick={() => setConfirmOpen(true)} disabled={!dirty}>
                  {t('admin.settings.save', 'Save')}
                </Button>
              )}
            </div>
          )}
          {!canEdit && (
            <p className="text-sm text-muted-foreground">
              {t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')}
            </p>
          )}
        </CardContent>
      </Card>
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        destructive={turningOff}
        title={
          turningOff
            ? t('admin.captcha.confirmOffTitle', 'Turn the CAPTCHA off?')
            : t('admin.captcha.confirmTitle', 'Change the CAPTCHA keys?')
        }
        desc={t(
          'admin.captcha.confirmDesc',
          'Applies at once to sign-up, request access and sign-in on every server. Recorded in the admin audit log (never the secret) and sent to every administrator.'
        )}
        onConfirm={save}
      />
    </>
  )
}
