'use client'

/**
 * Ports on resolved addresses: a port scan of a host name stores each open
 * port on the address it was found on, so a domain or subdomain shows the
 * open ports of the addresses it resolves to, with the address. Hidden when
 * the caller may not read them (the API's own refusal); addresses and ports
 * outside the caller's data scope are only counted.
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { useMemo } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Network } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable, EmptyState, RelativeTime, StackedCell } from '@/features/shared'
import { useResolvedPorts, type ResolvedPort } from '../hooks/use-resolved-ports'

/** Asset types whose page shows the section. */
export function hasResolvedPorts(type: string): boolean {
  return type === 'domain' || type === 'subdomain'
}

function serviceText(p: ResolvedPort): string {
  return [p.product, p.version].filter(Boolean).join(' ')
}

export function ResolvedPortsSection({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading } = useResolvedPorts(assetId)
  useSettleSignal(isLoading)

  const columns = useMemo<ColumnDef<ResolvedPort>[]>(
    () => [
      {
        id: 'port',
        header: t('assetPorts.col.port', 'Port'),
        cell: ({ row }) => (
          <Link
            href={`/assets/${row.original.port_id}`}
            className="font-mono text-sm hover:underline"
          >
            {row.original.port}
            {row.original.transport ? `/${row.original.transport}` : ''}
          </Link>
        ),
      },
      {
        id: 'address',
        header: t('assetPorts.col.address', 'Address'),
        cell: ({ row }) => (
          <Link
            href={`/assets/${row.original.address_id}`}
            className="font-mono text-sm break-all hover:underline"
          >
            {row.original.address}
          </Link>
        ),
      },
      {
        id: 'service',
        header: t('assetPorts.col.service', 'Service'),
        cell: ({ row }) => {
          const name = row.original.service
          const product = serviceText(row.original)
          if (!name && !product) {
            return (
              <span className="text-sm text-muted-foreground">
                {t('assetPorts.unknownService', 'Not identified')}
              </span>
            )
          }
          return <StackedCell primary={name || product} secondary={name ? product : undefined} />
        },
      },
      {
        id: 'lastSeen',
        header: t('assetPorts.col.lastSeen', 'Last seen'),
        cell: ({ row }) => (
          <RelativeTime date={row.original.last_seen} className="text-sm text-muted-foreground" />
        ),
      },
    ],
    [t]
  )

  // A refusal (no permission, out of scope) hides the section.
  if (error) return null

  const title = t('assetPorts.title', 'Ports on resolved addresses')
  return (
    <Card id="asset-resolved-ports">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">
          {t(
            'assetPorts.hint',
            'Open ports of the addresses this name resolves to. A port scan of the name records each port on the address it was found on.'
          )}
        </p>
        {isLoading || !data ? (
          <Skeleton className="h-24 w-full" />
        ) : data.items.length === 0 ? (
          <EmptyState
            icon={Network}
            card={false}
            title={t('assetPorts.emptyTitle', 'No open ports on record')}
            description={t(
              'assetPorts.emptyHint',
              'No port scan has found an open port on the addresses this name resolves to.'
            )}
          />
        ) : (
          <DataTable
            columns={columns}
            data={data.items}
            getRowId={(p) => p.port_id}
            showSearch={false}
            showColumnToggle={false}
            showPagination={data.items.length > 10}
          />
        )}
        {data && data.truncated && (
          <p className="text-sm text-muted-foreground" role="status">
            {t('assetPorts.truncated', 'Showing the first {count} ports.', {
              count: data.items.length.toLocaleString(),
            })}
          </p>
        )}
        {data && data.hidden_count > 0 && (
          <p className="text-sm text-muted-foreground" role="status">
            {t(
              'assetPorts.hidden',
              '{count} more ports are on addresses or ports outside your data scope.',
              { count: data.hidden_count.toLocaleString() }
            )}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
