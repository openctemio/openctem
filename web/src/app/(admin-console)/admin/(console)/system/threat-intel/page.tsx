'use client'

import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '@/features/admin-console/api/admin-client'
import {
  setThreatIntelEnabled,
  syncThreatIntel,
  useThreatIntelFeeds,
} from '@/features/admin-console/api/use-system'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { adminCan, type ThreatIntelFeed } from '@/features/admin-console/types'

const FEED_NAMES: Record<string, string> = {
  epss: 'EPSS (exploit prediction scores)',
  kev: 'CISA KEV (known exploited vulnerabilities)',
}

function statusTone(f: ThreatIntelFeed) {
  if (!f.enabled) return 'muted' as const
  if (f.last_sync_status === 'failed' || f.last_error) return 'destructive' as const
  if (f.last_sync_status === 'success') return 'success' as const
  return 'info' as const
}

export default function ThreatIntelFeedsPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const canWrite = adminCan(admin.role, 'ops_admin')
  const { data, error, isLoading, mutate } = useThreatIntelFeeds()
  const [busy, setBusy] = useState<string | null>(null)

  const act = async (key: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(key)
    try {
      await fn()
      toast.success(done)
      await mutate()
    } catch (err) {
      toast.error(
        err instanceof AdminApiError
          ? err.message
          : t('admin.confirm.failed', 'The action failed. Try again.')
      )
    } finally {
      setBusy(null)
    }
  }

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.threatIntel', 'Threat intelligence')}
        description={t(
          'admin.ti.description',
          'Platform-wide feeds every organization uses to prioritize findings. They sync on a schedule; run one now after an outage.'
        )}
      >
        {canWrite && (
          <Button
            size="sm"
            variant="outline"
            disabled={busy !== null}
            onClick={() =>
              act('all', () => syncThreatIntel('all'), t('admin.ti.synced', 'Sync finished.'))
            }
          >
            <RefreshCw className="me-2 size-4" />
            {t('admin.ti.syncAll', 'Sync all now')}
          </Button>
        )}
      </PageHeader>
      <div className="mt-5">
        {error ? (
          <ErrorState
            title="threat intelligence feeds"
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {data.map((f) => (
              <Card key={f.source}>
                <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
                  <div className="space-y-1">
                    <CardTitle className="text-base">{FEED_NAMES[f.source] ?? f.source}</CardTitle>
                    <TonePill
                      tone={statusTone(f)}
                      label={
                        f.enabled
                          ? f.last_sync_status || t('admin.ti.never', 'Never synced')
                          : t('admin.ti.off', 'Scheduled sync off')
                      }
                    />
                  </div>
                  <Switch
                    checked={f.enabled}
                    disabled={!canWrite || busy !== null}
                    aria-label={t('admin.ti.toggle', 'Scheduled sync for {feed}', {
                      feed: f.source,
                    })}
                    onCheckedChange={(on) =>
                      act(
                        f.source,
                        () => setThreatIntelEnabled(f.source, on),
                        on
                          ? t('admin.ti.enabled', 'Scheduled sync on.')
                          : t('admin.ti.disabled', 'Scheduled sync off.')
                      )
                    }
                  />
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <dl className="grid grid-cols-2 gap-y-1">
                    <dt className="text-muted-foreground">{t('admin.ti.last', 'Last sync')}</dt>
                    <dd>{f.last_sync_at ? <RelativeTime date={f.last_sync_at} /> : '-'}</dd>
                    <dt className="text-muted-foreground">{t('admin.ti.records', 'Records')}</dt>
                    <dd className="tabular-nums">{f.records_synced.toLocaleString()}</dd>
                    <dt className="text-muted-foreground">{t('admin.ti.next', 'Next sync')}</dt>
                    <dd>{f.next_sync_at ? <RelativeTime date={f.next_sync_at} /> : '-'}</dd>
                  </dl>
                  {f.last_error && (
                    <p className="text-sm break-words text-destructive">{f.last_error}</p>
                  )}
                  {canWrite && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy !== null}
                      onClick={() =>
                        act(
                          f.source,
                          () => syncThreatIntel(f.source),
                          t('admin.ti.synced', 'Sync finished.')
                        )
                      }
                    >
                      <RefreshCw className="me-2 size-4" />
                      {t('admin.ti.syncOne', 'Sync now')}
                    </Button>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </Main>
  )
}
