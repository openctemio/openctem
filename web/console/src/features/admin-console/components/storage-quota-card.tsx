'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { saveStorageQuota, useStorageQuota } from '../api/use-platform-settings'
import { SettingChangedLine, handleSaveConflict } from './console-setting-parts'

/**
 * Settings > Limits: the default storage quota (MiB of uploaded files per
 * organization). An organization's own storage limit (its Limits tab) wins.
 * Applies to the next upload; needs a super admin and the step-up.
 */
export function StorageQuotaCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const id = useId()
  const { data, error, isLoading, mutate } = useStorageQuota()
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (data) setValue(String(data.default_mb))
  }, [data])

  if (error) {
    return (
      <ErrorState
        title={t('admin.quota.errorTitle', 'the storage quota')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-40 w-full" />

  const n = /^\d+$/.test(value.trim()) ? Number(value.trim()) : NaN
  const valid = Number.isSafeInteger(n) && n >= 0 && n <= data.max_mb
  const dirty = valid && n !== data.default_mb

  const save = async () => {
    setBusy(true)
    try {
      await saveStorageQuota({ default_mb: n, version: data.version })
      toast.success(t('admin.quota.saved', 'Default storage quota saved'))
      void mutate()
    } catch (e) {
      if (
        !handleSaveConflict(
          e,
          () => void mutate(),
          t(
            'admin.settings.conflict',
            'Another administrator changed this setting. The latest values are shown.'
          )
        )
      )
        toast.error(
          e instanceof Error
            ? e.message
            : t('admin.settings.saveFailed', 'Could not save the setting')
        )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('admin.quota.title', 'Default storage quota')}</CardTitle>
        <CardDescription>
          {t(
            'admin.quota.description',
            "How much uploaded evidence and attachments one organization may keep, in MiB. An organization's own storage limit (its Limits tab) wins. 0 means no quota."
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid max-w-xs gap-1.5">
          <Label htmlFor={id}>{t('admin.quota.label', 'MiB per organization')}</Label>
          <Input
            id={id}
            inputMode="numeric"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            disabled={!canEdit}
            aria-invalid={!valid}
          />
          {!valid && (
            <p className="text-sm text-destructive">
              {t('admin.quota.invalid', 'A whole number from 0 to {max}.', { max: data.max_mb })}
            </p>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          {data.source === 'console'
            ? t(
                'admin.quota.sourceConsole',
                'Set in this console. The server default ({env}) is {mb} MiB.',
                {
                  env: data.env_var,
                  mb: data.environment_mb,
                }
              )
            : t(
                'admin.quota.sourceEnv',
                'From the server default ({env}) until you save a value here.',
                {
                  env: data.env_var,
                }
              )}
        </p>
        <SettingChangedLine change={data} />
        {canEdit && (
          <div className="flex justify-end">
            <Button onClick={() => void save()} disabled={!dirty || busy}>
              {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
              {t('admin.settings.save', 'Save')}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
