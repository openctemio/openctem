'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { toast } from 'sonner'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { ErrorState } from '@/features/shared'
import { saveFeedFreshnessLimits, useFeedFreshnessLimits } from '../api/use-platform-settings'
import {
  ReasonConfirmDialog,
  SettingChangedLine,
  handleSaveConflict,
} from './console-setting-parts'

/** A release older than this is refused, so no limit goes beyond it. */
const MAX_RELEASE_HOURS = 168

/** EPSS follows the bundle limit: a day more, at least 36 hours, at most 7 days. */
export function epssHoursFor(bundleHours: number): number {
  return Math.min(Math.max(36, bundleHours + 24), MAX_RELEASE_HOURS)
}

/**
 * System > Threat intelligence: how old the vulnerability data may be before
 * the cards show it as stale, the administrators are alerted and every user
 * sees the banner. The default suits a platform that receives the feed by
 * itself; a site that copies releases by hand raises it. KEV rides the
 * bundle and takes the same limit; EPSS a day more. A release older than 7
 * days is refused whatever the limit. Raising it also loosens which KEV and
 * EPSS copies of a release count as current. Super admin, fresh step-up and a
 * reason; a critical audit entry, every administrator is told.
 */
export function FeedFreshnessLimitsCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const id = useId()
  const { data, error, isLoading, mutate } = useFeedFreshnessLimits()
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)

  const reset = useCallback(() => {
    if (data) setValue(String(data.bundle_hours))
  }, [data])
  useEffect(reset, [reset])

  if (error) {
    return (
      <ErrorState
        title={t('admin.feedLimits.errorTitle', 'the vulnerability data age limit')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-40 w-full" />

  const n = /^\d+$/.test(value.trim()) ? Number(value.trim()) : NaN
  const valid = Number.isSafeInteger(n) && n >= data.min_hours && n <= data.max_hours
  const dirty = valid && n !== data.bundle_hours
  const shown = valid ? n : data.bundle_hours

  const save = async (reason: string) => {
    setBusy(true)
    try {
      await saveFeedFreshnessLimits({ bundle_hours: n, version: data.version, reason })
      toast.success(t('admin.feedLimits.saved', 'Vulnerability data age limit saved'))
      void mutate()
    } catch (e) {
      if (
        handleSaveConflict(
          e,
          () => void mutate(),
          t(
            'admin.settings.conflict',
            'Another administrator changed this setting. The latest values are shown.'
          )
        )
      )
        return
      throw e
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card data-testid="feed-freshness-limits">
      <CardHeader>
        <CardTitle>{t('admin.feedLimits.title', 'How old the data may be')}</CardTitle>
        <CardDescription>
          {t(
            'admin.feedLimits.description',
            'After this many hours without a newer release, the feeds show as stale, the administrators are alerted and every user sees the banner. Raising it also lets older KEV and EPSS copies in a release count as current, so new exploited vulnerabilities can show up later. Keep the default when the platform receives the feed by itself. Raise it only when you copy releases to an offline folder by hand. A release older than 7 days is refused whatever this says.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid max-w-xs gap-1.5">
          <Label htmlFor={id}>
            {t('admin.feedLimits.label', 'Vulnerability bundles and CISA KEV, in hours')}
          </Label>
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
              {t('admin.feedLimits.invalid', 'A whole number from {min} to {max}.', {
                min: data.min_hours,
                max: data.max_hours,
              })}
            </p>
          )}
        </div>
        <p className="text-sm text-muted-foreground">
          {t(
            'admin.feedLimits.epss',
            'EPSS scores are dated by day: their limit is {hours, plural, one {# hour} other {# hours}}.',
            {
              hours: epssHoursFor(shown),
            }
          )}
        </p>
        <p className="text-xs text-muted-foreground">
          {data.source === 'console'
            ? t(
                'admin.feedLimits.sourceConsole',
                'Set in this console. The default is {hours, plural, one {# hour} other {# hours}}.',
                {
                  hours: data.default_hours,
                }
              )
            : t('admin.feedLimits.sourceDefault', 'The default, until you save a value here.')}
        </p>
        <SettingChangedLine change={data} />
        {canEdit && (
          <SettingsSaveBar
            className="basis-full"
            dirty={dirty}
            saving={busy}
            onSave={() => setConfirmOpen(true)}
            onDiscard={reset}
          />
        )}
      </CardContent>
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t('admin.feedLimits.confirmTitle', 'Change how old the data may be?')}
        desc={t(
          'admin.feedLimits.confirmDesc',
          'Applies at the next check on every server. A higher limit hides out-of-date data for longer and accepts older KEV and EPSS copies. Recorded in the admin audit log and sent to every administrator.'
        )}
        confirmText={t('admin.feedLimits.confirmButton', 'Change the limit')}
        onConfirm={save}
      />
    </Card>
  )
}
