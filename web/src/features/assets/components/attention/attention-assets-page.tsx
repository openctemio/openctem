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
import { Lock } from 'lucide-react'
import { Main } from '@/components/layout'
import { EmptyState, PageHeader, PageStack } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import { useAssets, type AssetSearchFilters } from '../../hooks/use-assets'
import {
  attributionQuery,
  DEFAULT_PAGE_SIZE,
  serializeInventoryFilters,
} from '../../lib/inventory-url'
import type { Asset } from '../../types/asset.types'
import { AssetsSectionTabs } from '../assets-section-tabs'
import { AttentionQueueHeader } from './attention-queue-header'
import { ATTENTION_FILTERS, type AttentionReason } from './attention-filters'
import { InventoryBulkBar } from '../inventory/inventory-bulk-bar'
import { InventoryTable } from '../inventory/inventory-table'

export { ATTENTION_FILTERS, type AttentionReason }

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

  const title = t('assets.overview.title', 'Assets')

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

  return (
    <Main>
      <PageStack>
        <PageHeader title={title} />
        <AssetsSectionTabs />
        <AttentionQueueHeader
          reason={reason}
          count={isLoading ? undefined : total}
          inventoryHref={inventoryHref}
        />

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
      </PageStack>

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
