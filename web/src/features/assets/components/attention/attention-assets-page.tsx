'use client'

/**
 * Assets › Needs attention, the asset reasons (research/233 D8, 242 D3): the
 * assets that weaken priority, ownership or coverage, each reason a fixed
 * filter of the inventory (same list API, same data scope, same table and
 * bulk bar), so fixing one in bulk is one selection away. Relationship
 * suggestions and possible duplicates are the other reasons; they keep their
 * own pages under the same tabs.
 */

import { useEffect, useMemo, useState } from 'react'
import { Main } from '@/components/layout'
import { NoAccessState, PageHeader, PageStack } from '@/features/shared'
import { inSentence } from '@/features/asset-types/lib/type-view'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import { useAssets, type AssetSearchFilters } from '../../hooks/use-assets'
import {
  attributionQuery,
  DEFAULT_PAGE_SIZE,
  serializeInventoryFilters,
} from '../../lib/inventory-url'
import { AssetsSectionTabs } from '../assets-section-tabs'
import { AttentionQueueHeader } from './attention-queue-header'
import { ATTENTION_FILTERS, type AttentionReason } from './attention-filters'
import { useInventoryTableBulk } from '../inventory/inventory-bulk-bar'
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

  // The table draws the checkbox column and the bulk bar; a new page, size,
  // sort or reason starts with nothing selected.
  const tableBulk = useInventoryTableBulk({ canWrite, onDone: () => void mutate() })
  const clearSelection = tableBulk.clear
  useEffect(() => {
    clearSelection()
  }, [reason, page, pageSize, sort, clearSelection])

  const title = t('assets.overview.title', 'Assets')

  if (!canRead) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={title} />
          <NoAccessState title={inSentence(title)} permission={Permission.AssetsRead} />
        </PageStack>
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
          bulk={tableBulk.bulk}
          resetSelectionKey={tableBulk.resetKey}
          onAssetUpdated={() => void mutate()}
          hasFilters
          emptyMessage={t('assets.attention.empty', 'Nothing needs attention here')}
          emptyDescription={t(
            'assets.attention.emptyHint',
            'Every asset you can see has this covered.'
          )}
        />
      </PageStack>

      {tableBulk.dialogs}
    </Main>
  )
}
