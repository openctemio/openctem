'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, RelativeTime } from '@/features/shared'
import { saveThreatSource, useThreatSource } from '../api/use-platform-settings'
import { SettingChangedLine, handleSaveConflict } from './console-setting-parts'

/**
 * Threat intelligence page: where CISA KEV and EPSS come from. The signed
 * vulnerability release carries both; the platform's own fetch from CISA and
 * FIRST is the supplier (default) or a fallback for a stale release copy, and
 * strict-egress installs can forbid it. Needs a super admin and the step-up.
 */
export function ThreatSourceCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const bundleId = useId()
  const directId = useId()
  const { data, error, isLoading, mutate } = useThreatSource()
  const [bundle, setBundle] = useState(false)
  const [direct, setDirect] = useState(true)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (data) {
      setBundle(data.source === 'bundle')
      setDirect(data.direct_fetch === 'auto')
    }
  }, [data])

  if (error) {
    return (
      <ErrorState
        title={t('admin.ti.source.errorTitle', 'the feed source setting')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-48 w-full" />

  const dirty = bundle !== (data.source === 'bundle') || direct !== (data.direct_fetch === 'auto')

  const save = async () => {
    setBusy(true)
    try {
      await saveThreatSource({
        source: bundle ? 'bundle' : 'direct',
        direct_fetch: direct ? 'auto' : 'off',
        version: data.version,
      })
      toast.success(t('admin.ti.source.saved', 'Feed source saved'))
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
        <CardTitle>{t('admin.ti.source.title', 'Where KEV and EPSS come from')}</CardTitle>
        <CardDescription>
          {t(
            'admin.ti.source.description',
            "The signed vulnerability release carries CISA KEV and EPSS. By default the platform also fetches them itself on a schedule and applies the release's copy when it is newer."
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <Switch
              id={bundleId}
              checked={bundle}
              onCheckedChange={setBundle}
              disabled={!canEdit}
            />
            <Label htmlFor={bundleId}>
              {t('admin.ti.source.bundleLabel', 'Use the signed release as the source')}
            </Label>
          </div>
          <p className="text-sm text-muted-foreground">
            {t(
              'admin.ti.source.bundleHelp',
              "The platform fetches from CISA and FIRST only when the release's copy is stale (KEV older than 6 hours, EPSS older than 48 hours). Switch it on once the release below has been fresh for a week."
            )}
          </p>
        </div>
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <Switch
              id={directId}
              checked={direct}
              onCheckedChange={setDirect}
              disabled={!canEdit}
            />
            <Label htmlFor={directId}>
              {t('admin.ti.source.directLabel', 'Allow the platform to call CISA and FIRST')}
            </Label>
          </div>
          <p className="text-sm text-muted-foreground">
            {t(
              'admin.ti.source.directHelp',
              'Turn it off on installs with strict egress rules: the release is then the only source, and a stale copy shows as stale.'
            )}
          </p>
        </div>
        <ul className="space-y-1 text-sm">
          {data.feeds.map((f) => (
            <li key={f.source} className="flex flex-wrap items-center gap-x-3">
              <span className="font-medium">{f.source.toUpperCase()}</span>
              <span className="text-muted-foreground">
                {f.bundle_fetched_at ? (
                  <>
                    {t('admin.ti.source.releaseRead', 'Release copy read')}{' '}
                    <RelativeTime date={f.bundle_fetched_at} />
                    {', '}
                    {f.bundle_fresh
                      ? t('admin.ti.source.fresh', 'fresh')
                      : t('admin.ti.source.stale', 'stale')}
                  </>
                ) : (
                  t('admin.ti.source.noRelease', 'No release has carried this feed yet')
                )}
              </span>
              {f.delivered_via && (
                <span className="text-muted-foreground">
                  {f.delivered_via === 'bundle'
                    ? t('admin.ti.source.viaBundle', 'Data from the release')
                    : t('admin.ti.source.viaDirect', 'Data from the direct fetch')}
                </span>
              )}
            </li>
          ))}
        </ul>
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
