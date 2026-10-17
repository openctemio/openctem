'use client'

import { useState } from 'react'
import { History } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, RelativeTime } from '@/features/shared'
import { useLifecycleVersions, type LifecycleVersion } from '../../api/use-finding-lifecycles'
import { PublishDialog } from './publish-dialog'

interface LifecycleVersionsProps {
  lifecycleId: string
  canWrite: boolean
  onPublished: (v: LifecycleVersion) => void
}

/** A lifecycle's versions, newest first, with roll back to a superseded one. */
export function LifecycleVersions({ lifecycleId, canWrite, onPublished }: LifecycleVersionsProps) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useLifecycleVersions(lifecycleId)
  const [rollback, setRollback] = useState<number | null>(null)

  if (error) {
    return (
      <ErrorState
        title={t('findingLifecycle.versions.loadTitle', 'lifecycle versions')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-24 w-full rounded-lg" />

  const versions = [...(data.data ?? [])].sort((a, b) => b.version - a.version)
  if (versions.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {t('findingLifecycle.versions.empty', 'No versions yet')}
      </p>
    )
  }

  return (
    <>
      <ul className="divide-y rounded-lg border">
        {versions.map((v) => (
          <li
            key={v.version}
            className="flex flex-wrap items-center justify-between gap-2 px-3 py-2"
          >
            <div className="min-w-0 space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium tabular-nums">
                  {t('findingLifecycle.versions.version', 'Version {version}', {
                    version: v.version,
                  })}
                </span>
                <Badge
                  variant={v.state === 'published' ? 'default' : 'outline'}
                  className="text-xs"
                >
                  {t(`findingLifecycle.versions.state.${v.state}`, v.state)}
                </Badge>
              </div>
              <div className="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
                <RelativeTime date={v.published_at ?? v.created_at} className="text-xs" />
                {v.note && <span className="truncate">{v.note}</span>}
              </div>
            </div>
            {canWrite && v.state === 'superseded' && (
              <Button size="sm" variant="outline" onClick={() => setRollback(v.version)}>
                <History className="mr-1 size-3.5" />
                {t('findingLifecycle.versions.rollback', 'Roll back')}
              </Button>
            )}
          </li>
        ))}
      </ul>
      <PublishDialog
        open={rollback !== null}
        onOpenChange={(o) => !o && setRollback(null)}
        lifecycleId={lifecycleId}
        version={rollback ?? 0}
        rollback
        onPublished={(v) => {
          void mutate()
          onPublished(v)
        }}
      />
    </>
  )
}
