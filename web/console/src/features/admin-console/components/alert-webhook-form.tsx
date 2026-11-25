'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import {
  SettingsBlock,
  SettingsFieldGrid,
  SettingsRow,
  SettingsSaveBar,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
import { saveAlertWebhook, sendTestAlert } from '../api/use-platform-settings'
import type { AlertWebhookSettings } from '../types'
import {
  ReasonConfirmDialog,
  SecretField,
  SettingChangedLine,
  handleSaveConflict,
  secretPatch,
} from './console-setting-parts'

export interface AlertWebhookFormProps {
  settings: AlertWebhookSettings
  canEdit: boolean
  onSaved: () => void
}

/**
 * Settings > Alerts: an HTTPS webhook that receives the alerts sent to
 * administrators (low disk, stale backups, expiring certificates, setting
 * changes) next to the e-mail. The address is a credential, so it is
 * write-only like the signing secret; only its host is shown.
 */
export function AlertWebhookForm({ settings, canEdit, onSaved }: AlertWebhookFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [enabled, setEnabled] = useState(settings.enabled)
  const [url, setUrl] = useState('')
  const [clearUrl, setClearUrl] = useState(false)
  const [secret, setSecret] = useState('')
  const [clearSecret, setClearSecret] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [testing, setTesting] = useState(false)

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => {
    setEnabled(settings.enabled)
    setUrl('')
    setClearUrl(false)
    setSecret('')
    setClearSecret(false)
  }, [settings])
  useEffect(reset, [reset])

  const dirty =
    enabled !== settings.enabled || url !== '' || clearUrl || secret !== '' || clearSecret
  const willHaveUrl = (settings.url_set && !clearUrl) || url.trim() !== ''

  const test = async () => {
    setTesting(true)
    try {
      await sendTestAlert()
      toast.success(t('admin.alerts.testSent', 'The receiver accepted the test alert'))
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : t('admin.alerts.testFailed', 'The test alert failed')
      )
    } finally {
      setTesting(false)
    }
  }

  const save = async (reason: string) => {
    try {
      await saveAlertWebhook({
        enabled,
        url: secretPatch(url, clearUrl),
        secret: secretPatch(secret, clearSecret),
        reason,
        version: settings.version,
      })
      toast.success(t('admin.alerts.saved', 'Alert webhook saved'))
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
        id="alert-webhook"
        title={t('admin.alerts.title', 'Alert webhook')}
        description={t(
          'admin.alerts.description',
          'Sends the alerts administrators get by email to a chat or paging tool too: low disk space, stale backups, expiring certificates and changes to these settings. Checks that must run while the API is down stay with the server monitoring.'
        )}
        meta={<SettingChangedLine change={settings} />}
      >
        <SettingsSwitchRow
          id={`${id}-enabled`}
          label={t('admin.alerts.enabled', 'Send alerts to the webhook')}
          hint={
            settings.url_host
              ? t('admin.alerts.receiver', 'Receiver: {host}', { host: settings.url_host })
              : t('admin.alerts.noReceiver', 'No address is set yet.')
          }
          checked={enabled}
          onCheckedChange={setEnabled}
          disabled={!canEdit || (!willHaveUrl && !enabled)}
        />
        <SettingsBlock>
          <SettingsFieldGrid>
            <SecretField
              label={t('admin.alerts.url', 'Webhook address (https)')}
              isSet={settings.url_set}
              value={url}
              onChange={setUrl}
              clear={clearUrl}
              onClear={setClearUrl}
              disabled={!canEdit}
              placeholder="https://hooks.example.com/..."
              help={t(
                'admin.alerts.urlHelp',
                'Write-only, like a password: such addresses often carry a token. Internal addresses are refused.'
              )}
            />
            <SecretField
              label={t('admin.alerts.secret', 'Signing secret (optional)')}
              isSet={settings.secret_set}
              value={secret}
              onChange={setSecret}
              clear={clearSecret}
              onClear={setClearSecret}
              disabled={!canEdit}
              help={t(
                'admin.alerts.secretHelp',
                'With a secret, each request is signed so you can check it came from this platform. The signature and the time are sent in the request headers.'
              )}
            />
          </SettingsFieldGrid>
          {enabled && !willHaveUrl && (
            <p role="alert" className="text-dense text-destructive">
              {t('admin.alerts.needsUrl', 'Set an address to turn the webhook on.')}
            </p>
          )}
        </SettingsBlock>
        {canEdit && (
          <SettingsRow
            label={t('admin.alerts.test', 'Send a test alert')}
            hint={t(
              'admin.alerts.testHint',
              'Sends one test alert to the saved address. Save or discard your changes first.'
            )}
          >
            <Button
              variant="outline"
              onClick={() => void test()}
              disabled={testing || dirty || !settings.url_set}
            >
              {testing && <Loader2 className="animate-spin" aria-hidden />}
              {t('admin.alerts.testButton', 'Send test')}
            </Button>
          </SettingsRow>
        )}
      </SettingsSection>
      {canEdit && (
        <SettingsSaveBar
          dirty={dirty}
          saveDisabled={enabled && !willHaveUrl}
          onSave={() => setConfirmOpen(true)}
          onDiscard={reset}
        />
      )}
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        destructive={settings.enabled && !enabled}
        title={t('admin.alerts.confirmTitle', 'Change where alerts go?')}
        desc={t(
          'admin.alerts.confirmDesc',
          'The previous receiver is told first. Recorded in the admin audit log (never the address or secret) and sent to every administrator.'
        )}
        confirmText={t('admin.alerts.confirmButton', 'Change alert receiver')}
        onConfirm={save}
      />
    </>
  )
}
