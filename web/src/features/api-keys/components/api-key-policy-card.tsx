'use client'

import { useEffect, useState } from 'react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSection } from '@/features/shared/components/settings-section'
import { SettingsRow } from '@/features/shared/components/settings-fields'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { getErrorMessage } from '@/lib/api/error-handler'

import { updateApiKeyPolicy, useApiKeyPolicy } from '../api/use-api-keys'

/**
 * The organization's maximum lifetime of a new API key (owners and
 * administrators), a framed section of the API keys settings page. A shorter
 * maximum saves at once; a longer one asks for confirmation and, on the API
 * side, a recent sign-in, and tells every owner and administrator. Existing
 * keys keep their expiry and are flagged in the list when they outlive the
 * maximum.
 */
export function APIKeyPolicySection({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const { data, mutate } = useApiKeyPolicy()
  const [draft, setDraft] = useState<number | null>(null)
  const [saving, setSaving] = useState(false)
  const [confirm, setConfirm] = useState(false)

  useEffect(() => {
    if (data) setDraft(data.max_lifetime_days)
  }, [data])

  if (!data || draft === null) return null

  const valid = Number.isInteger(draft) && draft >= 1 && draft <= data.ceiling_days
  const dirty = draft !== data.max_lifetime_days

  const save = async () => {
    setSaving(true)
    try {
      const next = await updateApiKeyPolicy(draft)
      await mutate(next, { revalidate: false })
      toast.success(t('settings.apiKeys.policy.saved', 'Maximum key lifetime saved'))
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const onSave = () => {
    if (!dirty || !valid || saving) return
    if (draft > data.max_lifetime_days) {
      setConfirm(true)
      return
    }
    void save()
  }

  return (
    <SettingsSection
      framed
      id="api-key-max-lifetime"
      title={t('settings.apiKeys.policy.title', 'Maximum key lifetime')}
      description={t(
        'settings.apiKeys.policy.description',
        'New keys may live at most this many days. Existing keys keep their expiry; a key that outlives the maximum is marked in the list.'
      )}
    >
      <SettingsRow
        wide
        label={
          <label htmlFor="api-key-max-days">
            {t('settings.apiKeys.policy.days', 'Days (1 to {max})', { max: data.ceiling_days })}
          </label>
        }
        hintId="api-key-max-days-hint"
        hint={
          <span className={valid ? undefined : 'text-destructive'}>
            {t(
              'settings.apiKeys.policy.hint',
              'Default {default} days. The platform allows at most {max}.',
              { default: data.default_max_lifetime_days, max: data.ceiling_days }
            )}
          </span>
        }
      >
        <Input
          id="api-key-max-days"
          className="max-w-40"
          type="number"
          inputMode="numeric"
          min={1}
          max={data.ceiling_days}
          step={1}
          value={Number.isNaN(draft) ? '' : draft}
          disabled={!canEdit || saving}
          aria-invalid={!valid}
          aria-describedby="api-key-max-days-hint"
          onChange={(e) => setDraft(e.target.valueAsNumber)}
        />
      </SettingsRow>

      {canEdit && (
        <SettingsSaveBar
          dirty={dirty}
          saving={saving}
          onSave={onSave}
          onDiscard={() => setDraft(data.max_lifetime_days)}
        />
      )}

      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={t('settings.apiKeys.policy.confirmTitle', 'Allow longer-lived keys?')}
        desc={t(
          'settings.apiKeys.policy.confirmDesc',
          'A leaked key stays usable for longer. You may be asked to sign in again. Owners and administrators are told, and the change is audited.'
        )}
        confirmText={t('settings.apiKeys.policy.confirm', 'Save')}
        handleConfirm={async () => {
          await save()
          setConfirm(false)
        }}
      />
    </SettingsSection>
  )
}
