'use client'

import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '@console/lib/admin-api/client'
import {
  failedSyncResults,
  setThreatIntelEnabled,
  syncThreatIntel,
  useThreatIntelFeeds,
} from '@console/features/admin-console/api/use-system'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { adminCan } from '@console/features/admin-console/types'
import { BundleDetail } from '@console/features/admin-console/components/bundle-detail'
import { FeedCard } from '@console/features/admin-console/components/feed-card'
import { feedName } from '@console/features/admin-console/lib/feed-status'

export default function ThreatIntelFeedsPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const canWrite = adminCan(admin.role, 'ops_admin')
  const { data, error, isLoading, mutate } = useThreatIntelFeeds()
  const [busy, setBusy] = useState<string | null>(null)

  // A sync answers 200 even when a feed failed: the outcome is per feed.
  const runSync = async (key: string, source: string) => {
    setBusy(key)
    try {
      const failed = failedSyncResults(await syncThreatIntel(source))
      if (failed.length === 0) {
        toast.success(t('admin.ti.synced', 'Sync finished.'))
      } else {
        for (const r of failed) {
          toast.error(
            t('admin.ti.syncFailed', '{feed} did not sync: {error}', {
              feed: feedName(r.source, t),
              error: r.error || t('admin.confirm.failed', 'The action failed. Try again.'),
            })
          )
        }
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
