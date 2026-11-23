'use client'

/**
 * Assets › Needs attention, the asset reasons (research/233 D8, 242 D3): the
 * assets that weaken priority, ownership or coverage, each reason a fixed
 * filter of the inventory (same list API, same data scope, same table and
 * bulk bar), so fixing one in bulk is one selection away. Relationship
 * suggestions and possible duplicates are the other reasons; they keep their
 * own pages under the same tabs.
 */

import { useEffect, useMemo } from 'react'
import { Main } from '@/components/layout'
import {
  ErrorState,
  NoAccessState,
  PageHeader,
  PageStack,
  usePhoneSelectMode,
} from '@/features/shared'
import { inSentence } from '@/features/asset-types/lib/type-view'
import { useTranslation } from '@/context/i18n-provider'
import { useIsMobile } from '@/hooks/use-mobile'
import { useListParams } from '@/hooks/use-list-params'
import { accessStateOf } from '@/lib/api/access-state'
import { Permission, usePermissions } from '@/lib/permissions'
import { useAssets, type AssetSearchFilters } from '../../hooks/use-assets'
import { attributionQuery, serializeInventoryFilters, SORT_FIELDS } from '../../lib/inventory-url'
import { AssetsSectionTabs } from '../assets-section-tabs'
import { AttentionQueueHeader } from './attention-queue-header'
import { ATTENTION_FILTERS, type AttentionReason } from './attention-filters'
import { useInventoryTableBulk } from '../inventory/inventory-bulk-bar'
import { InventoryTable } from '../inventory/inventory-table'

export { ATTENTION_FILTERS, type AttentionReason }

/** Riskiest first: the order of every Needs attention queue at rest. */
const DEFAULT_SORT = '-risk_score'

export function AttentionAssetsPage({ reason }: { reason: AttentionReason }) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.AssetsRead)
  const canWrite = can(Permission.AssetsWrite)
  const isPhone = useIsMobile()
  // Page, size and sort live in the address, so a queue position can be
  // linked to and survives a reload (riskiest first by default).
  const list = useListParams({
    sortFields: Object.values(SORT_FIELDS),
    defaultSort: DEFAULT_SORT,
  })
  const { page, perPage: pageSize, sort, searchTerm } = list

  const base = ATTENTION_FILTERS[reason]
  const query = useMemo<AssetSearchFilters>(
    () => ({
      ...base,
      search: searchTerm || undefined,
      attribution: attributionQuery(base),
      withTriage: true,
      sort,
      page,
      pageSize,
    }),
    [base, searchTerm, sort, page, pageSize]
  )
  const { assets, total, totalCapped, isLoading, hasLoaded, error, mutate } = useAssets(query)
  // The first read draws skeleton rows; a later one keeps the rows on screen.
  const firstLoad = isLoading && !hasLoaded
  const noAccess = !!error && accessStateOf(error) === 'no_access'

  // The table draws the checkbox column and the bulk bar; a new page, size,
  // sort or reason starts with nothing selected.
  const tableBulk = useInventoryTableBulk({ canWrite, onDone: () => void mutate() })
  const clearSelection = tableBulk.clear
  useEffect(() => {
    clearSelection()
  }, [reason, page, pageSize, sort, searchTerm, clearSelection])
  // Phone cards have no header checkbox: "Select" is in the queue's More.
  const phoneSelect = usePhoneSelectMode(isPhone && !!tableBulk.bulk)

  const title = t('assets.overview.title', 'Assets')

  if (!canRead || noAccess) {
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
          count={firstLoad || error ? undefined : total}
          inventoryHref={inventoryHref}
          moreItems={phoneSelect.item ? [phoneSelect.item] : undefined}
        />

        <InventoryTable
          assets={assets}
          total={total}
          totalCapped={totalCapped}
          page={page}
          pageSize={pageSize}
          sort={sort}
          onPageChange={(p, size) => list.setPagination({ pageIndex: p - 1, pageSize: size })}
          onSortChange={(next) =>
            list.setSorting(
              next ? [{ id: next.replace(/^-/, ''), desc: next.startsWith('-') }] : []
            )
          }
          // The queue's search, as on the inventory: the toolbar holds it with
          // the Display menu, so the list starts under one toolbar row.
          search={{
            value: list.q,
            onChange: list.setSearch,
            placeholder: isPhone
              ? t('assets.inventoryPage.searchShort', 'Search assets…')
              : t('assets.inventoryPage.search', 'Search name, description or alias…'),
            label: t('assets.inventoryPage.searchAria', 'Search assets'),
          }}
          onClearFilters={() => list.setSearch('')}
          isLoading={firstLoad}
          isRefreshing={isLoading && hasLoaded}
          // A failed read keeps the queue's header; the table says what failed.
          errorState={
            error ? (
              <ErrorState
                title={t('assets.inventoryPage.errorTitle', 'assets')}
                error={error}
                onRetry={() => void mutate()}
              />
            ) : undefined
          }
          bulk={tableBulk.bulk}
          selectMode={phoneSelect.selectMode}
          resetSelectionKey={tableBulk.resetKey}
          onAssetUpdated={() => void mutate()}
          hasFilters
          // With a search, an empty queue is "no match" (with Clear), not "all done".
          emptyMessage={
            searchTerm ? undefined : t('assets.attention.empty', 'Nothing needs attention here')
          }
          emptyDescription={
            searchTerm
              ? undefined
              : t('assets.attention.emptyHint', 'Every asset you can see has this covered.')
          }
        />
      </PageStack>

      {tableBulk.dialogs}
    </Main>
  )
}
