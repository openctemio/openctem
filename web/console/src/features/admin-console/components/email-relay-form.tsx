'use client'

import { useEffect, useId, useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { saveEmailRelay } from '../api/use-platform-settings'
import type { EmailRelayMode, EmailRelaySettings } from '../types'
import {
  ReasonConfirmDialog,
  SettingChangedLine,
  handleSaveConflict,
} from './console-setting-parts'

export interface EmailRelayFormProps {
  settings: EmailRelaySettings
  canEdit: boolean
  onSaved: () => void
}

const MODES: EmailRelayMode[] = ['off', 'verified_sender', 'on']

/**
 * Settings > E-mail > Organization mail servers (research 308, D12): whether
 * an organization's own mail server carries its organization mail
 * (invitations, member notices, reports). Account security mail never does,
 * whatever the mode. A change needs a super admin with a fresh code and a
 * reason, applies at once and every administrator is told.
 */
export function EmailRelayForm({ settings, canEdit, onSaved }: EmailRelayFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [mode, setMode] = useState<EmailRelayMode>(settings.mode)
  const [confirmOpen, setConfirmOpen] = useState(false)
  useEffect(() => setMode(settings.mode), [settings])

  const label: Record<EmailRelayMode, string> = {
    off: t('admin.emailRelay.off', 'Never'),
    verified_sender: t('admin.emailRelay.verified', 'Only from a verified domain'),
    on: t('admin.emailRelay.on', 'Always, as configured'),
  }
  const hint: Record<EmailRelayMode, string> = {
    off: t('admin.emailRelay.offHint', 'All mail goes through this deployment’s server.'),
    verified_sender: t(
      'admin.emailRelay.verifiedHint',
      'The sender must be on a domain the organization has verified, over a secure connection.'
    ),
    on: t('admin.emailRelay.onHint', 'The organization’s server is used whenever it is set.'),
  }

  const save = async (reason: string) => {
    try {
      await saveEmailRelay({ mode, reason, version: settings.version })
      toast.success(t('admin.emailRelay.saved', 'Organization mail setting saved'))
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
          <CardTitle>{t('admin.emailRelay.title', 'Organization mail servers')}</CardTitle>
          <CardDescription>
            {t(
              'admin.emailRelay.description',
              'When an organization’s own server sends its invitations, notices and reports. Sign-in and account security mail always uses this deployment’s server.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <RadioGroup
            value={mode}
            onValueChange={(v) => setMode(v as EmailRelayMode)}
            disabled={!canEdit}
            aria-label={t('admin.emailRelay.title', 'Organization mail servers')}
            className="gap-2"
          >
            {MODES.map((m) => (
              <div key={m} className="flex items-start gap-3 rounded-lg border p-3">
                <RadioGroupItem value={m} id={`${id}-${m}`} className="mt-0.5" />
                <div className="space-y-0.5">
                  <Label htmlFor={`${id}-${m}`} className="font-medium">
                    {label[m]}
                  </Label>
                  <p className="text-xs text-muted-foreground">{hint[m]}</p>
                </div>
              </div>
            ))}
          </RadioGroup>
          <p className="text-xs text-muted-foreground">
            {settings.source === 'default'
              ? t('admin.emailRelay.sourceDefault', 'Server default ({name}).', {
                  name: settings.env_var,
                })
              : t('admin.emailRelay.sourceConsole', 'Set in this console.')}
          </p>
          <SettingChangedLine change={settings} />
          {canEdit ? (
            <div className="flex justify-end">
              <Button onClick={() => setConfirmOpen(true)} disabled={mode === settings.mode}>
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
        destructive={mode === 'on'}
        title={t('admin.emailRelay.confirmTitle', 'Change who sends organization mail?')}
        desc={t(
          'admin.emailRelay.confirmDesc',
          'Applies at once to every organization. Recorded in the admin audit log and sent to every administrator.'
        )}
        confirmText={t('admin.emailRelay.confirmButton', 'Save mail setting')}
        onConfirm={save}
      />
    </>
  )
}
