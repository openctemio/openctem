'use client'

import { useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import type { ContentInstall } from '@/lib/api/generated'
import { Badge } from '@/components/ui/badge'
import { DataTable, ErrorState, RelativeTime, StackedCell } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useContentInstalls } from '../api'

/** What this organization has installed: one row per package, bounded by the catalog. */
export function InstalledTab({ onOpen }: { onOpen: (packageId: string) => void }) {
  const { t } = useTranslation()
  const installs = useContentInstalls()

  const columns = useMemo<ColumnDef<ContentInstall>[]>(
    () => [
      {
        id: 'package',
        header: t('contentCatalog.col.package', 'Package'),
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.installed?.title || row.original.package_id}
            secondary={row.original.package_id}
          />
        ),
      },
      {
        id: 'type',
        header: t('contentCatalog.col.type', 'Type'),
        cell: ({ row }) =>
          row.original.installed?.type ? (
            <Badge variant="outline">
              {t(`contentCatalog.type.${row.original.installed.type}`, row.original.installed.type)}
            </Badge>
          ) : null,
      },
      {
        id: 'version',
        header: t('contentCatalog.col.version', 'Version'),
        cell: ({ row }) => (
          <span className="flex flex-wrap items-center gap-1">
            <span className="font-mono text-sm">{row.original.installed?.version}</span>
            {row.original.pinned && (
              <Badge variant="outline">{t('contentCatalog.pinned', 'Pinned')}</Badge>
            )}
          </span>
        ),
      },
      {
        id: 'status',
        header: t('contentCatalog.col.status', 'Status'),
        cell: ({ row }) =>
          row.original.status === 'revoked' ? (
            <Badge variant="destructive">{t('contentCatalog.revoked', 'Revoked')}</Badge>
          ) : (
            <Badge variant="secondary">{t('contentCatalog.status.active', 'Active')}</Badge>
          ),
      },
      {
        id: 'updated',
        header: t('contentCatalog.col.updated', 'Updated'),
        cell: ({ row }) => <RelativeTime date={row.original.updated_at} />,
      },
    ],
    [t]
  )

  if (installs.error) {
    return (
      <ErrorState
        title={t('contentCatalog.installedWhat', 'the installed content')}
        error={installs.error}
        onRetry={() => void installs.mutate()}
      />
    )
  }

  return (
    <DataTable
      columns={columns}
      data={installs.data ?? []}
      getRowId={(i) => i.package_id ?? ''}
      isLoading={installs.isLoading}
      showSearch={false}
      showColumnToggle={false}
      showSelectionCount={false}
      mobileCards
      onRowClick={(i) => i.package_id && onOpen(i.package_id)}
      emptyMessage={t('contentCatalog.emptyInstalled', 'Nothing is installed yet')}
    />
  )
}
