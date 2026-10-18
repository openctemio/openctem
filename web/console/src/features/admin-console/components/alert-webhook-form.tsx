'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
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

  useEffect(() => {
    setEnabled(settings.enabled)
    setUrl('')
    setClearUrl(false)
    setSecret('')
    setClearSecret(false)
  }, [settings])

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
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.alerts.title', 'Alert webhook')}</CardTitle>
          <CardDescription>
            {t(
              'admin.alerts.description',
              'Sends the alerts administrators get by e-mail to a chat or paging tool too: low disk space, stale backups, expiring certificates and changes to these settings. Checks that must run while the API is down stay with the server monitoring.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
            <Label htmlFor={`${id}-enabled`} className="grid gap-1 font-normal">
              <span className="font-medium">
                {t('admin.alerts.enabled', 'Send alerts to the webhook')}
              </span>
              <span className="text-sm text-muted-foreground">
                {settings.url_host
                  ? t('admin.alerts.receiver', 'Receiver: {host}', { host: settings.url_host })
                  : t('admin.alerts.noReceiver', 'No address is set yet.')}
              </span>
            </Label>
            <Switch
              id={`${id}-enabled`}
              checked={enabled}
              onCheckedChange={setEnabled}
              disabled={!canEdit || (!willHaveUrl && !enabled)}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
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
                'With a secret, each request carries X-OpenCTEM-Timestamp and X-OpenCTEM-Signature (sha256 HMAC of the timestamp, a dot and the body).'
              )}
            />
          </div>
          {enabled && !willHaveUrl && (
            <p className="text-sm text-destructive">
              {t('admin.alerts.needsUrl', 'Set an address to turn the webhook on.')}
            </p>
          )}
          <SettingChangedLine change={settings} />
          {canEdit ? (
            <div className="flex flex-wrap items-center justify-end gap-3">
              <Button
                variant="outline"
                onClick={() => void test()}
                disabled={testing || dirty || !settings.url_set}
              >
                {testing && <Loader2 className="me-1.5 size-4 animate-spin" />}
                {t('admin.alerts.test', 'Send a test alert')}
              </Button>
              <Button
                onClick={() => setConfirmOpen(true)}
                disabled={!dirty || (enabled && !willHaveUrl)}
              >
                {t('admin.settings.save', 'Save')}
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')}
            </p>
          )}
        </CardContent>
      </Card>
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        destructive={settings.enabled && !enabled}
        title={t('admin.alerts.confirmTitle', 'Change where alerts go?')}
        desc={t(
          'admin.alerts.confirmDesc',
          'The previous receiver is told first. Recorded in the admin audit log (never the address or secret) and sent to every administrator.'
        )}
        onConfirm={save}
      />
    </>
  )
}
