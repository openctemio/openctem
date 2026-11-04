'use client'

import * as React from 'react'
import { useId } from 'react'
import { toast } from 'sonner'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { SettingsSaveBar, SettingsSection } from '@/features/shared'
import { updateCredentialSettings } from '../api/use-credentials-api'
import type { ApiCredentialSettings } from '../api/credential-api.types'

type Choice = 'default' | 'on' | 'off'

const CHOICES: Choice[] = ['default', 'on', 'off']

function toChoice(s: ApiCredentialSettings): Choice {
  if (s.store_secret_values === undefined || s.store_secret_values === null) return 'default'
  return s.store_secret_values ? 'on' : 'off'
}

export interface CredentialStorageSettingsFormProps {
  settings: ApiCredentialSettings
  onSaved: (saved: ApiCredentialSettings) => void
}

/**
 * Settings > Leaked credentials: whether an imported leaked secret value
 * (password, token, key) is kept, encrypted, for an audited reveal. Not kept:
 * only the masked form, the credential type and the organization's
 * fingerprint are stored. The organization's choice wins over the platform
 * default; it applies to the next import.
 */
export function CredentialStorageSettingsForm({
  settings,
  onSaved,
}: CredentialStorageSettingsFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const saved = toChoice(settings)
  const [choice, setChoice] = React.useState<Choice>(saved)
  const [saving, setSaving] = React.useState(false)
  React.useEffect(() => setChoice(saved), [saved])
  const dirty = choice !== saved

  const platformDefault = settings.platform_default
    ? t('credentials.settings.defaultKeeps', 'keeps values')
    : t('credentials.settings.defaultDrops', 'does not keep values')
  const label: Record<Choice, string> = {
    default: t('credentials.settings.choiceDefault', 'Platform default ({value})', {
      value: platformDefault,
    }),
    on: t('credentials.settings.choiceOn', 'Keep secret values'),
    off: t('credentials.settings.choiceOff', 'Do not keep secret values'),
  }
  const hint: Record<Choice, string> = {
    default: t(
      'credentials.settings.choiceDefaultHint',
      'Follows the setting of the platform administrator.'
    ),
    on: t(
      'credentials.settings.choiceOnHint',
      'Encrypted at rest. People with the Reveal Credential Secrets permission can read a value; every reveal is audited.'
    ),
    off: t(
      'credentials.settings.choiceOffHint',
      'Only the masked form, the credential type and a fingerprint are stored. Nothing can be revealed.'
    ),
  }

  const save = async () => {
    setSaving(true)
    try {
      const body = choice === 'default' ? {} : { store_secret_values: choice === 'on' }
      const res = await updateCredentialSettings(body)
      toast.success(t('credentials.settings.saved', 'Leaked credential settings saved'))
      onSaved(res)
    } catch (e) {
      toast.error(getErrorMessage(e, t('credentials.settings.saveFailed', 'Could not save')))
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <SettingsSection
        id={`${id}-title`}
        title={t('credentials.settings.storageTitle', 'Secret values')}
        description={t(
          'credentials.settings.storageDescription',
          'Whether the password, token or key of an imported leaked credential is kept. The fingerprint is keyed to your organization, so the same secret matches across your own leaks only.'
        )}
      >
        <RadioGroup
          value={choice}
          onValueChange={(v) => setChoice(v as Choice)}
          aria-labelledby={`${id}-title`}
          className="gap-2"
        >
          {CHOICES.map((c) => (
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
          {t(
            'credentials.settings.appliesNext',
            'Applies to the next import. Values already kept stay until the credential is deleted.'
          )}
        </p>
      </SettingsSection>
      <SettingsSaveBar
        dirty={dirty}
        saving={saving}
        onSave={() => void save()}
        onDiscard={() => setChoice(saved)}
      />
    </>
  )
}
