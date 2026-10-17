'use client'

import * as React from 'react'
import { Layers } from 'lucide-react'

import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, RelativeTime } from '@/features/shared'
import { cn } from '@/lib/utils'

import { useAssetTechnologies } from '../../hooks/use-asset-technologies'
import { groupByCategory, useCategoryLabel } from './technologies-by-category'

/**
 * The asset's Technologies tab (RFC-112): every technology probes detected,
 * grouped by category, with version, the tool's confidence, the source and
 * first and last seen. A row per technology; on a phone each row stacks.
 */
export function AssetTechnologiesTab({
  assetId,
  className,
}: {
  assetId: string
  className?: string
}) {
  const { t } = useTranslation()
  const label = useCategoryLabel()
  const { data, error, isLoading, mutate } = useAssetTechnologies(assetId)

  if (isLoading) {
    return (
      <div className={cn('space-y-2', className)} aria-busy="true">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    )
  }
  if (error) {
    return (
      <div className={className}>
        <ErrorState
          title={t('assets.technologies.listName', 'the technology list')}
          error={error}
          onRetry={() => void mutate()}
        />
      </div>
    )
  }
  const items = data ?? []
  if (items.length === 0) {
    return (
      <EmptyState
        icon={Layers}
        title={t('assets.technologies.emptyTitle', 'No technologies detected')}
        description={t(
          'assets.technologies.emptyHint',
          'Technologies appear when a web probe fingerprints the asset: its web server, frameworks, JavaScript libraries, CDN, hosting, WAF, analytics tags and security headers.'
        )}
        className={className}
      />
    )
  }
  return (
    <div className={cn('space-y-4', className)}>
      {groupByCategory(items).map((g) => (
        <section key={g.category} aria-label={label(g.category)} className="space-y-1.5">
          <h4 className="text-xs font-medium text-muted-foreground">
            {label(g.category)} <span className="tabular-nums">({g.items.length})</span>
          </h4>
          <ul className="divide-y rounded-lg border">
            {g.items.map((item) => (
              <li
                key={item.name}
                className="grid gap-1 px-3 py-2 text-sm sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-center sm:gap-4"
              >
                <span className="min-w-0 break-words">
                  <span className="font-medium">{item.name}</span>
                  {item.version && <span className="ml-1.5 tabular-nums">{item.version}</span>}
                </span>
                <span className="text-xs text-muted-foreground">
                  {[
                    item.confidence
                      ? t('assets.technologies.confidence', 'Confidence {value}', {
                          value: item.confidence,
                        })
                      : null,
                    item.source
                      ? t('assets.technologies.source', 'Source: {source}', { source: item.source })
                      : null,
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                </span>
                <span className="text-xs text-muted-foreground">
                  {t('assets.technologies.firstSeen', 'First seen')}{' '}
                  <RelativeTime date={item.first_seen_at} />
                  {' · '}
                  {t('assets.technologies.lastSeen', 'Last seen')}{' '}
                  <RelativeTime date={item.last_seen_at} />
                </span>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  )
}
