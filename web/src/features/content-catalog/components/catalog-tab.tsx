'use client'

import { useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Search } from 'lucide-react'
import type { ContentPackageListItem } from '@/lib/api/generated'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { DataTable, ErrorState, StackedCell } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import { useContentPackages } from '../api'
import { CONTENT_TYPES } from '../lib'

const ANY = 'any'

export function CatalogTab({ onOpen }: { onOpen: (packageId: string) => void }) {
  const { t } = useTranslation()
  const list = useListParams({ defaultPageSize: 20, filters: { type: '', installed: '' } })
  const q = useDebounce(list.q, 300)
  const type = (CONTENT_TYPES as readonly string[]).includes(list.filters.type)
    ? list.filters.type
    : ''
  const installed =
    list.filters.installed === 'true' || list.filters.installed === 'false'
      ? list.filters.installed
      : ''
  const packages = useContentPackages({
    type,
    q,
    installed,
    page: list.page,
    perPage: list.perPage,
  })

  const columns = useMemo<ColumnDef<ContentPackageListItem>[]>(
    () => [
      {
        id: 'package',
        header: t('contentCatalog.col.package', 'Package'),
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.latest?.title || row.original.latest?.package_id}
            secondary={row.original.latest?.package_id}
          />
        ),
      },
      {
        id: 'type',
        header: t('contentCatalog.col.type', 'Type'),
        cell: ({ row }) =>
          row.original.latest?.type ? (
            <Badge variant="outline">
              {t(`contentCatalog.type.${row.original.latest.type}`, row.original.latest.type)}
            </Badge>
          ) : null,
      },
      {
        id: 'latest',
        header: t('contentCatalog.col.latest', 'Latest'),
        cell: ({ row }) => (
          <span className="font-mono text-sm">
            {row.original.latest?.version}
            {(row.original.versions ?? 0) > 1 && (
              <span className="ms-1 font-sans text-xs text-muted-foreground">
                {t('contentCatalog.versionsCount', '({n} versions)', {
                  n: row.original.versions ?? 0,
                })}
              </span>
            )}
          </span>
        ),
      },
      {
        id: 'tier',
        header: t('contentCatalog.perm.tier', 'Tier'),
        cell: ({ row }) => (
          <span className="font-mono text-sm">{row.original.latest?.permissions?.tier}</span>
        ),
      },
      {
        id: 'installed',
        header: t('contentCatalog.col.installed', 'Installed'),
        cell: ({ row }) => {
          const ins = row.original.install
          if (!ins) return <span className="text-sm text-muted-foreground">-</span>
          return (
            <span className="flex flex-wrap items-center gap-1">
              <Badge variant={ins.status === 'revoked' ? 'destructive' : 'secondary'}>
                {ins.installed?.version}
              </Badge>
              {ins.pinned && (
                <Badge variant="outline">{t('contentCatalog.pinned', 'Pinned')}</Badge>
              )}
            </span>
          )
        },
      },
    ],
    [t]
  )

  if (packages.error) {
    return (
      <ErrorState
        title={t('contentCatalog.catalogWhat', 'the catalog')}
        error={packages.error}
        onRetry={() => void packages.mutate()}
      />
    )
  }

  return (
    <DataTable
      columns={columns}
      data={packages.data?.data ?? []}
      getRowId={(p) => p.latest?.package_id ?? ''}
      isLoading={packages.isLoading}
      showSearch={false}
      showColumnToggle={false}
      showSelectionCount={false}
      mobileCards
      onRowClick={(p) => p.latest?.package_id && onOpen(p.latest.package_id)}
      emptyMessage={t('contentCatalog.emptyCatalog', 'No package matches')}
      manualPagination
      pageCount={Math.max(1, Math.ceil((packages.data?.total ?? 0) / list.perPage))}
      rowCount={packages.data?.total ?? 0}
      pagination={list.pagination}
      onPaginationChange={list.setPagination}
      toolbarStart={
        <div className="flex w-full flex-col gap-2 sm:flex-row">
          <div className="relative w-full sm:max-w-xs">
            <Search
              className="absolute start-2.5 top-2.5 size-4 text-muted-foreground"
              aria-hidden
            />
            <Input
              value={list.q}
              maxLength={100}
              onChange={(e) => list.setSearch(e.target.value)}
              placeholder={t('contentCatalog.search', 'Search packages')}
              aria-label={t('contentCatalog.search', 'Search packages')}
              className="ps-8"
            />
          </div>
          <Select
            value={type || ANY}
            onValueChange={(v) => list.setFilter('type', v === ANY ? '' : v)}
          >
            <SelectTrigger className="sm:w-48" aria-label={t('contentCatalog.col.type', 'Type')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>{t('contentCatalog.anyType', 'Any type')}</SelectItem>
              {CONTENT_TYPES.map((k) => (
                <SelectItem key={k} value={k}>
                  {t(`contentCatalog.type.${k}`, k)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            value={installed || ANY}
            onValueChange={(v) => list.setFilter('installed', v === ANY ? '' : v)}
          >
            <SelectTrigger
              className="sm:w-44"
              aria-label={t('contentCatalog.col.installed', 'Installed')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>{t('contentCatalog.filter.all', 'All packages')}</SelectItem>
              <SelectItem value="true">
                {t('contentCatalog.filter.installed', 'Installed')}
              </SelectItem>
              <SelectItem value="false">
                {t('contentCatalog.filter.notInstalled', 'Not installed')}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
      }
    />
  )
}
