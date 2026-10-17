'use client'

import { useEffect, useState } from 'react'
import { GitBranch, Plus } from 'lucide-react'
import { mutate as globalMutate } from 'swr'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { EmptyState, ErrorState, GatedButton, SettingsSection } from '@/features/shared'
import {
  lifecycleVersionsKey,
  useLifecycles,
  type LifecycleSubStatus,
} from '../../api/use-finding-lifecycles'
import { LifecycleCreateDialog } from './lifecycle-create-dialog'
import { LifecycleDraftEditor } from './lifecycle-draft-editor'
import { LifecycleVersions } from './lifecycle-versions'

interface LifecycleSchemesProps {
  catalog: LifecycleSubStatus[]
  canWrite: boolean
  /** The plan allows no more lifecycles (null: unknown or unlimited). */
  limit: { limit: number; used: number; reached: boolean } | null
}

/** The organization's lifecycles: pick one, edit its draft, see its versions. */
export function LifecycleSchemes({ catalog, canWrite, limit }: LifecycleSchemesProps) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useLifecycles()
  const [selected, setSelected] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const lifecycles = (data?.data ?? []).filter((l) => !l.archived)
  useEffect(() => {
    if (!selected && lifecycles.length > 0) setSelected(lifecycles[0].id)
  }, [lifecycles, selected])

  if (error) {
    return (
      <ErrorState
        title={t('findingLifecycle.scheme.loadTitle', 'finding lifecycles')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-64 w-full rounded-xl" />

  const current = lifecycles.find((l) => l.id === selected) ?? lifecycles[0]
  const limitReached = limit?.reached ?? false
  const newButton = (
    <GatedButton
      allowed={canWrite && !limitReached}
      reason={
        limitReached
          ? t('findingLifecycle.plan.schemesReachedShort', 'Limit of lifecycles reached')
          : t('findingLifecycle.readOnly', 'Needs the Manage Finding Lifecycles permission')
      }
      size="sm"
      onClick={() => setCreating(true)}
    >
      <Plus className="mr-1 size-3.5" />
      {t('findingLifecycle.scheme.new', 'New lifecycle')}
    </GatedButton>
  )

  return (
    <div className="space-y-6">
      {lifecycles.length === 0 ? (
        <EmptyState
          icon={GitBranch}
          title={t('findingLifecycle.scheme.emptyTitle', 'The platform lifecycle applies')}
          description={
            limit && limit.limit === 0
              ? t(
                  'findingLifecycle.plan.schemesNone',
                  'Only sub-statuses are available for this organization. Custom moves and requirements are not.'
                )
              : t(
                  'findingLifecycle.scheme.emptyHint',
                  'Create a lifecycle to add moves between sub-statuses and the requirements each needs.'
                )
          }
          action={newButton}
        />
      ) : (
        <>
          <SettingsSection
            title={t('findingLifecycle.scheme.listTitle', 'Lifecycles')}
            description={
              limit
                ? t('findingLifecycle.plan.usage', '{used} of {limit} used', {
                    used: limit.used,
                    limit: limit.limit,
                  })
                : undefined
            }
            actions={newButton}
          >
            <div role="tablist" className="flex flex-wrap gap-2">
              {lifecycles.map((l) => (
                <button
                  key={l.id}
                  type="button"
                  role="tab"
                  aria-selected={current?.id === l.id}
                  onClick={() => setSelected(l.id)}
                  className={cn(
                    'flex min-w-0 items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm',
                    current?.id === l.id ? 'border-primary bg-accent' : 'hover:bg-muted/50'
                  )}
                >
                  <span className="truncate font-medium">{l.name}</span>
                  {l.default && (
                    <Badge variant="outline" className="text-xs">
                      {t('findingLifecycle.scheme.default', 'Default')}
                    </Badge>
                  )}
                  <span className="text-xs text-muted-foreground">
                    {l.published
                      ? t('findingLifecycle.scheme.publishedVersion', 'v{version} in force', {
                          version: l.published.version,
                        })
                      : t('findingLifecycle.scheme.unpublished', 'Not published')}
                  </span>
                </button>
              ))}
            </div>
          </SettingsSection>

          {current && (
            <div className="space-y-6">
              {current.description && (
                <p className="text-sm text-muted-foreground">{current.description}</p>
              )}
              <LifecycleDraftEditor
                key={current.id}
                lifecycle={current}
                catalog={catalog}
                canWrite={canWrite}
                onReload={() => {
                  void mutate()
                  void globalMutate(lifecycleVersionsKey(current.id))
                }}
              />
              <SettingsSection
                title={t('findingLifecycle.versions.title', 'Version history')}
                description={t(
                  'findingLifecycle.versions.hint',
                  'Published versions never change. Rolling back publishes an older one again as a new version.'
                )}
              >
                <LifecycleVersions
                  lifecycleId={current.id}
                  canWrite={canWrite}
                  onPublished={() => void mutate()}
                />
              </SettingsSection>
            </div>
          )}
        </>
      )}
      <LifecycleCreateDialog
        open={creating}
        onOpenChange={setCreating}
        hasDefault={lifecycles.some((l) => l.default)}
        onCreated={(l) => {
          setSelected(l.id)
          void mutate()
        }}
      />
    </div>
  )
}
