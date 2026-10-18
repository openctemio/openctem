'use client'

import { useId, useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { setRegion, useRegionSettings } from '../api/use-platform-settings'
import {
  LockedByEnvironment,
  ReasonConfirmDialog,
  SettingChangedLine,
} from './console-setting-parts'

const REGION_RE = /^[a-z0-9][a-z0-9-]{0,31}$/

/**
 * The deployment region: the data region every new organization is stamped
 * with. Set once, only before the first organization exists, then fixed.
 */
export function DeploymentRegionCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const id = useId()
  const { data, error, isLoading, mutate } = useRegionSettings()
  const [value, setValue] = useState('')
  const [confirmOpen, setConfirmOpen] = useState(false)

  if (error) {
    return (
      <ErrorState
        title={t('admin.region.errorTitle', 'the deployment region')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-32 w-full" />

  const valid = REGION_RE.test(value.trim())
  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="text-base">
              {t('admin.region.title', 'Deployment region')}
            </CardTitle>
            <TonePill
              tone={data.region ? 'success' : 'muted'}
              label={data.region ? data.region : t('admin.region.notSet', 'Not set')}
            />
          </div>
          <CardDescription>
            {t(
              'admin.region.description',
              'The data region every new organization is stamped with, shown to its people. It can be set once, before the first organization exists, and never changes afterwards.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {data.locked_by_environment && <LockedByEnvironment envVar={data.env_var} />}
          {!data.locked_by_environment && data.region && (
            <p className="text-sm text-muted-foreground">
              {t('admin.region.fixed', 'Set in this console; it cannot be changed.')}
            </p>
          )}
          {!data.region && !data.settable && (
            <p className="text-sm text-muted-foreground">
              {t(
                'admin.region.tooLate',
                'Organizations already exist, so a region can no longer be set: it would differ from theirs.'
              )}
            </p>
          )}
          {data.settable && canEdit && (
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
              <div className="grid flex-1 gap-1.5">
                <Label htmlFor={id}>{t('admin.region.label', 'Region name')}</Label>
                <Input
                  id={id}
                  value={value}
                  onChange={(e) => setValue(e.target.value.toLowerCase())}
                  placeholder="eu-central"
                  maxLength={32}
                  aria-invalid={value !== '' && !valid}
                />
              </div>
              <Button onClick={() => setConfirmOpen(true)} disabled={!valid}>
                {t('admin.region.set', 'Set the region')}
              </Button>
            </div>
          )}
          {data.settable && canEdit && value !== '' && !valid && (
            <p className="text-sm text-destructive">
              {t(
                'admin.region.invalid',
                '1-32 lowercase letters, digits or hyphens, e.g. eu-central.'
              )}
            </p>
          )}
          {data.settable && !canEdit && (
            <p className="text-sm text-muted-foreground">
              {t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')}
            </p>
          )}
          <SettingChangedLine change={data} />
        </CardContent>
      </Card>
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        destructive
        title={t(
          'admin.region.confirmTitle',
          'Set the region to {region}? This cannot be undone.',
          {
            region: value.trim(),
          }
        )}
        desc={t(
          'admin.region.confirmDesc',
          'Every organization created from now on gets this region, and it can never be changed. Recorded in the admin audit log and sent to every administrator.'
        )}
        onConfirm={async (reason) => {
          await setRegion({ region: value.trim(), reason })
          toast.success(t('admin.region.saved', 'Deployment region set'))
          setValue('')
          void mutate()
        }}
      />
    </>
  )
}
