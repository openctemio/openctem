'use client'

/**
 * Assets › Needs attention, the asset reasons (research/233 D8, 242 D3): the
 * assets that weaken priority, ownership or coverage, each reason a fixed
 * filter of the inventory (same list API, same data scope, same table and
 * bulk bar), so fixing one in bulk is one selection away. Relationship
 * suggestions and possible duplicates are the other reasons; they keep their
 * own pages under the same tabs.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { ArrowRight, Lock } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { EmptyState, PageHeader } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import { safeHref } from '@/lib/safe-href'
import { useAssets, type AssetSearchFilters } from '../../hooks/use-assets'
import {
  attributionQuery,
  DEFAULT_PAGE_SIZE,
  serializeInventoryFilters,
  type InventoryFilters,
} from '../../lib/inventory-url'
import type { Asset } from '../../types/asset.types'
import { AssetAttentionTabs, AssetsSectionTabs } from '../assets-section-tabs'
import { InventoryBulkBar } from '../inventory/inventory-bulk-bar'
import { InventoryTable } from '../inventory/inventory-table'

export type AttentionReason = 'no_owner' | 'context' | 'unscanned'

/** Each reason as an inventory filter: the list here and the inventory link agree. */
export const ATTENTION_FILTERS: Record<AttentionReason, InventoryFilters> = {
  no_owner: { hasOwner: false },
  context: { criticalities: ['none'] },
  unscanned: { coverage: 'uncovered' },
}

const COPY: Record<AttentionReason, { key: string; fallback: string }> = {
  no_owner: {
    key: 'assets.attention.noOwner',
    fallback:
      '{count, plural, one {# asset has no owner} other {# assets have no owner}}. Findings on them have nobody to assign to.',
  },
  context: {
    key: 'assets.attention.context',
    fallback:
      '{count, plural, one {# asset has no criticality} other {# assets have no criticality}}. Priority uses the default for them.',
  },
  unscanned: {
    key: 'assets.attention.unscanned',
    fallback:
      '{count, plural, one {# asset had no successful scan} other {# assets had no successful scan}} in 30 days.',
  },
}

export function AttentionAssetsPage({ reason }: { reason: AttentionReason }) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.AssetsRead)
  const canWrite = can(Permission.AssetsWrite)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE)
  const [sort, setSort] = useState<string | undefined>('-risk_score')

  const base = ATTENTION_FILTERS[reason]
  const query = useMemo<AssetSearchFilters>(
    () => ({
      ...base,
      attribution: attributionQuery(base),
      withTriage: true,
      sort,
      page,
      pageSize,
    }),
    [base, sort, page, pageSize]
  )
  const { assets, total, isLoading, mutate } = useAssets(query)

  const [selected, setSelected] = useState<Asset[]>([])
  const [epoch, setEpoch] = useState(0)
  const clearSelection = useCallback(() => {
    setEpoch((n) => n + 1)
    setSelected([])
  }, [])
  useEffect(() => {
    clearSelection()
  }, [reason, page, pageSize, sort, clearSelection])

  const title = t('assets.attention.title', 'Needs attention')
  const description = t(
    'assets.attention.description',
    'Assets whose missing owner, criticality or scan weakens priority, assignment or coverage. Fix them in bulk here.'
  )

  if (!canRead) {
    return (
      <Main>
        <PageHeader title={title} />
        <EmptyState
          className="mt-8 border-dashed"
          icon={Lock}
          title={t('assets.inventoryPage.noAccess', "You don't have access to assets")}
          description={t(
            'assets.inventoryPage.noAccessHint',
            'Ask an administrator for the assets:read permission to view the inventory.'
          )}
        />
      </Main>
    )
  }

  const inventoryHref = `/assets?${serializeInventoryFilters(base).toString()}`
  const copy = COPY[reason]

  return (
    <Main>
      <PageHeader title={title} description={description} />
      <AssetsSectionTabs />
      <AssetAttentionTabs />

      <div
        className="mt-5 flex flex-wrap items-center gap-3 rounded-lg border px-4 py-2.5 text-sm"
        data-testid="attention-summary"
      >
        <span className="min-w-0 flex-1">
          {isLoading ? ' ' : t(copy.key, copy.fallback, { count: total })}
        </span>
        <Button asChild variant="outline" size="sm">
          <Link href={safeHref(inventoryHref) ?? '/assets'}>
            {t('assets.attention.openInInventory', 'Open in the inventory')}
            <ArrowRight className="ms-1.5 h-3.5 w-3.5" aria-hidden />
          </Link>
        </Button>
      </div>

      <div className="mt-4">
        <InventoryTable
          assets={assets}
          total={total}
          page={page}
          pageSize={pageSize}
          sort={sort}
          onPageChange={(p, size) => {
            setPageSize(size)
            setPage(size !== pageSize ? 1 : p)
          }}
          onSortChange={(next) => {
            setSort(next)
            setPage(1)
          }}
          onSelectionChange={setSelected}
          resetSelectionKey={epoch}
          onAssetUpdated={() => void mutate()}
          hasFilters
          emptyMessage={t('assets.attention.empty', 'Nothing needs attention here')}
          emptyDescription={t(
            'assets.attention.emptyHint',
            'Every asset you can see has this covered.'
          )}
        />
      </div>

      <InventoryBulkBar
        selected={selected}
        canWrite={canWrite}
        onClear={clearSelection}
        onDone={() => {
          clearSelection()
          void mutate()
        }}
      />
    </Main>
  )
}
