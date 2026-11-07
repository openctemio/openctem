'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { toast } from 'sonner'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { saveLeakedSecretStorage } from '../api/use-platform-settings'
import type { LeakedSecretStorageSettings } from '../types'
import {
  ReasonConfirmDialog,
  SettingChangedLine,
  handleSaveConflict,
} from './console-setting-parts'

export interface LeakedSecretStorageFormProps {
  settings: LeakedSecretStorageSettings
  canEdit: boolean
  onSaved: () => void
}

type Choice = 'keep' | 'drop'

/**
 * System > Leaked credentials: the default, for organizations that never
 * chose, of whether an imported leaked secret value (password, token, key)
 * is kept, encrypted. Not kept: only the mask, the credential type and the
 * organization's keyed fingerprint. An organization's own choice wins. A
 * change needs a super admin with a fresh code and a reason, applies at once
 * and every administrator is told.
 */
export function LeakedSecretStorageForm({
  settings,
  canEdit,
  onSaved,
}: LeakedSecretStorageFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const saved: Choice = settings.store_by_default ? 'keep' : 'drop'
  const [choice, setChoice] = useState<Choice>(saved)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const reset = useCallback(() => setChoice(saved), [saved])
  useEffect(reset, [reset])
  const dirty = choice !== saved

  const label: Record<Choice, string> = {
    keep: t('admin.leakedSecrets.keep', 'Keep secret values'),
    drop: t('admin.leakedSecrets.drop', 'Do not keep secret values'),
  }
  const hint: Record<Choice, string> = {
    keep: t(
      'admin.leakedSecrets.keepHint',
      'Encrypted at rest; members with the reveal permission can read them, and every reveal is audited.'
    ),
    drop: t(
      'admin.leakedSecrets.dropHint',
      'Only the masked form, the credential type and a fingerprint keyed to the organization are stored.'
    ),
  }

  const save = async (reason: string) => {
    try {
      await saveLeakedSecretStorage({
        store_by_default: choice === 'keep',
        reason,
        version: settings.version,
      })
      toast.success(t('admin.leakedSecrets.saved', 'Leaked credential default saved'))
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
          <CardTitle>{t('admin.leakedSecrets.title', 'Leaked secret values')}</CardTitle>
          <CardDescription>
            {t(
              'admin.leakedSecrets.description',
              'Whether the password, token or key of an imported leaked credential is kept, for organizations that have not chosen. Each organization can change it for itself.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <RadioGroup
            value={choice}
            onValueChange={(v) => setChoice(v as Choice)}
            disabled={!canEdit}
            aria-label={t('admin.leakedSecrets.title', 'Leaked secret values')}
            className="gap-2"
          >
            {(['keep', 'drop'] as Choice[]).map((c) => (
              <div key={c} className="flex items-start gap-3 rounded-lg border p-3">
                <RadioGroupItem value={c} id={`${id}-${c}`} className="mt-0.5" />
                <div className="space-y-0.5">
                  <Label htmlFor={`${id}-${c}`} className="font-medium">
                    {label[c]}
                  </Label>
                  <p className="text-xs text-muted-foreground">{hint[c]}</p>
                </div>
              </div>
            ))}
          </RadioGroup>
          <p className="text-xs text-muted-foreground">
            {settings.source === 'default'
              ? settings.default
                ? t(
                    'admin.leakedSecrets.sourceDefaultKeep',
                    'Server default: kept (self-managed install).'
                  )
                : t(
                    'admin.leakedSecrets.sourceDefaultDrop',
                    'Server default: not kept (managed service).'
                  )
              : t('admin.leakedSecrets.sourceConsole', 'Set in this console.')}
          </p>
          <SettingChangedLine change={settings} />
          {canEdit ? (
            <SettingsSaveBar
              className="basis-full"
              dirty={dirty}
              onSave={() => setConfirmOpen(true)}
              onDiscard={reset}
            />
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
        destructive={choice === 'keep'}
        title={t('admin.leakedSecrets.confirmTitle', 'Change the leaked secret default?')}
        desc={t(
          'admin.leakedSecrets.confirmDesc',
          'Applies to the next import of every organization that has not chosen. Values already kept stay. Recorded in the admin audit log and sent to every administrator.'
        )}
        confirmText={t('admin.leakedSecrets.confirmButton', 'Save default')}
        onConfirm={save}
      />
    </>
  )
}
