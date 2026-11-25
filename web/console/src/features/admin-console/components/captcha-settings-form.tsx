'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import {
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsRow,
  SettingsSaveBar,
  SettingsSection,
  TonePill,
} from '@/features/shared'
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

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => {
    setSiteKey(settings.site_key)
    setSecret('')
    setClearSecret(false)
  }, [settings])
  useEffect(reset, [reset])

  const dirty = siteKey.trim() !== settings.site_key || secret !== '' || clearSecret
  const turningOff = clearSecret && siteKey.trim() === ''

  const check = async () => {
    setChecking(true)
    try {
      const { result } = await verifyCaptchaSecret(secret.trim() || undefined)
      if (result === 'valid')
        toast.success(t('admin.captcha.checkValid', 'The CAPTCHA service accepts this secret key'))
      else if (result === 'invalid')
        toast.error(
          t('admin.captcha.checkInvalid', 'The CAPTCHA service does not know this secret key')
        )
      else
        toast.warning(
          t(
            'admin.captcha.checkUnreachable',
            'The CAPTCHA service could not be reached; nothing is known about the key'
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
      <SettingsSection
        framed
        id="captcha-keys"
        title={t('admin.captcha.title', 'Cloudflare Turnstile keys')}
        // The state leads the description (a state, not an action): beside
        // the text it squeezed the description into a narrow column on a phone.
        description={
          <>
            <TonePill
              className="me-2 align-middle"
              tone={settings.secret_set ? 'success' : 'warning'}
              label={
                settings.secret_set ? t('admin.captcha.on', 'On') : t('admin.captcha.off', 'Off')
              }
            />
            {t(
              'admin.captcha.description',
              'Protects registration, the request-access form and every sign-in after repeated failures, for organizations and this console. Without keys only the rate limits apply.'
            )}
          </>
        }
        meta={<SettingChangedLine change={settings} />}
      >
        {locked && (
          <SettingsBlock>
            <LockedByEnvironment envVar={settings.env_var} />
          </SettingsBlock>
        )}
        <SettingsBlock>
          <SettingsFieldGrid>
            <SettingsField
              id={`${id}-site`}
              label={t('admin.captcha.siteKey', 'Site key (public)')}
            >
              {(control) => (
                <Input
                  {...control}
                  value={siteKey}
                  onChange={(e) => setSiteKey(e.target.value)}
                  disabled={!editable}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="0x4AAAAAAA..."
                />
              )}
            </SettingsField>
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
          </SettingsFieldGrid>
          {clearSecret && siteKey.trim() !== '' && (
            <p role="alert" className="text-dense text-destructive">
              {t(
                'admin.captcha.bothKeys',
                'Set both keys, or remove both: clear the site key too to turn the CAPTCHA off.'
              )}
            </p>
          )}
        </SettingsBlock>
        {canEdit && (
          <SettingsRow
            label={t('admin.captcha.check', 'Check the secret key')}
            hint={t(
              'admin.captcha.checkHint',
              'Asks the CAPTCHA service whether it knows the typed secret, or the stored one when the field is empty.'
            )}
          >
            <Button
              variant="outline"
              onClick={() => void check()}
              disabled={checking || (!settings.secret_set && secret.trim() === '')}
            >
              {checking && <Loader2 className="animate-spin" aria-hidden />}
              {t('admin.captcha.checkButton', 'Check')}
            </Button>
          </SettingsRow>
        )}
      </SettingsSection>
      {canEdit && !locked && (
        <SettingsSaveBar dirty={dirty} onSave={() => setConfirmOpen(true)} onDiscard={reset} />
      )}
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
        confirmText={
          turningOff
            ? t('admin.captcha.confirmOffButton', 'Turn CAPTCHA off')
            : t('admin.captcha.confirmButton', 'Change CAPTCHA keys')
        }
        onConfirm={save}
      />
    </>
  )
}
