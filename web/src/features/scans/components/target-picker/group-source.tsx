'use client'

/**
 * Asset groups source of the target picker. A group's members are resolved
 * by the server when the scan runs (members outside the creator's scope are
 * skipped then), so the picker never adds its member count to the target
 * total. The count shown is the API's, which follows the viewer's scope.
 */

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useAssetGroups } from '@/features/asset-groups'
import { PickerList } from './picker-list'

/** Asset groups listed at once (the API's largest page). */
export const GROUP_PAGE_SIZE = 100

interface GroupSourceProps {
  /** Picked group names by id. */
  selected: Record<string, string>
  onToggle: (group: { id: string; name: string }, picked: boolean) => void
}

export function GroupSource({ selected, onToggle }: GroupSourceProps) {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const debounced = useSearchQuery(search).term
  const { data, total, isLoading } = useAssetGroups({
    filters: {
      per_page: GROUP_PAGE_SIZE,
      sort_by: 'name',
      sort_order: 'asc',
      search: debounced || undefined,
    },
  })
  const groups = data ?? []

  return (
    <PickerList
      search={search}
      onSearch={setSearch}
      searchPlaceholder={t('scans.groups.searchPlaceholder')}
      searchLabel={t('scans.groups.search')}
      listLabel={t('scans.groups.list')}
      loading={isLoading}
      emptyText={
        debounced
          ? t('scans.groups.noMatch', undefined, { query: debounced })
          : t('scans.groups.none')
      }
      rows={groups.map((g) => ({
        id: g.id,
        label: g.name,
        picked: selected[g.id] !== undefined,
        trailing: (
          <Badge variant="outline" className="shrink-0 text-xs">
            {t(
              g.assetCount === 1 ? 'scans.groups.assetsOne' : 'scans.groups.assetsMany',
              undefined,
              {
                count: (g.assetCount ?? 0).toLocaleString(),
              }
            )}
          </Badge>
        ),
      }))}
      onToggle={(row, picked) => onToggle({ id: row.id, name: row.label }, picked)}
      footer={
        <p className="text-xs text-muted-foreground">
          {total > groups.length
            ? `${t('scans.groups.showing', undefined, { shown: groups.length, total })} `
            : ''}
          {t('scans.groups.resolvedAtRun')}
        </p>
      }
    />
  )
}
