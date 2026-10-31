'use client'

import { useEffect, useState } from 'react'
import { Timer } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { getErrorMessage } from '@/lib/api/error-handler'

import { updateApiKeyPolicy, useApiKeyPolicy } from '../api/use-api-keys'

/**
 * The organization's maximum lifetime of a new API key (owners and
 * administrators). A shorter maximum saves at once; a longer one asks for
 * confirmation and, on the API side, a recent sign-in, and tells every owner
 * and administrator. Existing keys keep their expiry and are flagged in the
 * list when they outlive the maximum.
 */
export function APIKeyPolicyCard({ canEdit }: { canEdit: boolean }) {
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
    <Card id="api-key-max-lifetime">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Timer className="h-5 w-5" aria-hidden />
          {t('settings.apiKeys.policy.title', 'Maximum key lifetime')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.apiKeys.policy.description',
            'New keys may live at most this many days. Existing keys keep their expiry; a key that outlives the maximum is marked in the list.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="max-w-xs space-y-1">
          <Label htmlFor="api-key-max-days">
            {t('settings.apiKeys.policy.days', 'Days (1 to {max})', { max: data.ceiling_days })}
          </Label>
          <Input
            id="api-key-max-days"
            type="number"
            min={1}
            max={data.ceiling_days}
            step={1}
            value={Number.isNaN(draft) ? '' : draft}
            disabled={!canEdit || saving}
            aria-invalid={!valid}
            onChange={(e) => setDraft(e.target.valueAsNumber)}
          />
          <p className={valid ? 'text-xs text-muted-foreground' : 'text-xs text-destructive'}>
            {t(
              'settings.apiKeys.policy.hint',
              'Default {default} days. The platform allows at most {max}.',
              { default: data.default_max_lifetime_days, max: data.ceiling_days }
            )}
          </p>
        </div>

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
      </CardContent>
    </Card>
  )
}
