'use client'

import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '@console/lib/admin-api/client'
import {
  setThreatIntelEnabled,
  syncThreatIntel,
  useThreatIntelFeeds,
} from '@console/features/admin-console/api/use-system'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { adminCan } from '@console/features/admin-console/types'
import { BundleDetail } from '@console/features/admin-console/components/bundle-detail'
import { FeedCard } from '@console/features/admin-console/components/feed-card'
import { feedName, feedProblem } from '@console/features/admin-console/lib/feed-status'

export default function ThreatIntelFeedsPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const canWrite = adminCan(admin.role, 'ops_admin')
  const [watching, setWatching] = useState<Record<string, string | null>>({})
  const { data, error, isLoading, mutate } = useThreatIntelFeeds(Object.keys(watching).length > 0)
  const [busy, setBusy] = useState<string | null>(null)

  // Sync requests the server queued: source -> the attempt time seen when it
  // was requested. A feed settles when it is no longer running and has a newer
  // attempt; the toast then reports the real outcome.
  const watchedSources = Object.keys(watching)

  const reason = (r: string | undefined) => {
    switch (r) {
      case 'disabled':
        return t('admin.ti.skip.disabled', 'its scheduled sync is off')
      case 'not_configured':
        return t('admin.ti.skip.not_configured', 'bundle import is not configured')
      case 'rate_limited':
        return t('admin.ti.skip.rate_limited', 'it was just started')
      default:
        return t('admin.ti.skip.other', 'it cannot run now')
    }
  }

  const runSync = async (key: string, source: string) => {
    setBusy(key)
    try {
      const res = await syncThreatIntel(source)
      const queued: Record<string, string | null> = {}
      for (const r of res?.results ?? []) {
        if (r.status === 'skipped') {
          toast.error(
            t('admin.ti.notStarted', '{feed} was not started: {reason}.', {
              feed: feedName(r.source, t),
              reason: reason(r.reason),
            })
          )
        } else {
          queued[r.source] = data?.find((f) => f.source === r.source)?.last_attempt_at ?? null
        }
      }
      if (Object.keys(queued).length > 0) {
        toast.success(t('admin.ti.started', 'Sync started. The result shows on the card.'))
        setWatching((w) => ({ ...w, ...queued }))
      }
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

  // Report the outcome of each requested sync once it settles; stop watching
  // after two minutes whatever happened.
  useEffect(() => {
    if (!data || watchedSources.length === 0) return
    const settled: string[] = []
    for (const source of watchedSources) {
      const f = data.find((x) => x.source === source)
      if (!f || f.state === 'running' || f.last_attempt_at === watching[source]) continue
      settled.push(source)
      const problem = feedProblem(f, t)
      if (problem) {
        toast.error(`${feedName(source, t)}: ${problem.message}`)
      } else {
        toast.success(t('admin.ti.syncedFeed', '{feed} synced.', { feed: feedName(source, t) }))
      }
    }
    if (settled.length > 0) {
      setWatching((w) =>
        Object.fromEntries(Object.entries(w).filter(([k]) => !settled.includes(k)))
      )
    }
  }, [data, watching, watchedSources, t])

  useEffect(() => {
    if (watchedSources.length === 0) return
    const timer = setTimeout(() => setWatching({}), 120_000)
    return () => clearTimeout(timer)
  }, [watchedSources.length])

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
      <PageStack>
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
              onClick={() => void runSync('all', 'all')}
            >
              <RefreshCw className="me-2 size-4" />
              {t('admin.ti.syncAll', 'Sync all now')}
            </Button>
          )}
        </PageHeader>
        {error ? (
          <ErrorState
            title={t(
              'admin.systemThreatIntelPage.threatIntelligenceFeeds',
              'threat intelligence feeds'
            )}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {[...data]
              .sort((x, y) => (x.source === 'vulnfeed' ? -1 : y.source === 'vulnfeed' ? 1 : 0))
              .map((f) => (
                <FeedCard
                  key={f.source}
                  feed={f}
                  canWrite={canWrite}
                  busy={busy !== null}
                  className={f.source === 'vulnfeed' ? 'lg:col-span-2' : undefined}
                  onSync={() => void runSync(f.source, f.source)}
                  onToggle={(on) =>
                    act(
                      f.source,
                      () => setThreatIntelEnabled(f.source, on),
                      on
                        ? t('admin.ti.enabled', 'Scheduled sync on.')
                        : t('admin.ti.disabled', 'Scheduled sync off.')
                    )
                  }
                >
                  <BundleDetail feed={f} />
                </FeedCard>
              ))}
          </div>
        )}
      </PageStack>
    </Main>
  )
}
