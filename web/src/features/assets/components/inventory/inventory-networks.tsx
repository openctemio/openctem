'use client'

/**
 * Group by network: the networks (the /24 of IPv4, the /64 of IPv6) of the
 * addresses the filter lists, most addresses first. A click filters the list to
 * one network. Replaces the table rows; the filter bar above stays.
 */

import { Network } from 'lucide-react'
import { EmptyState, ErrorState } from '@/features/shared'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import type { AssetNetworkCount } from '../../hooks/use-assets'
import { networkFilter } from '../../lib/ip-columns'

export function InventoryNetworks({
  networks,
  capped,
  isLoading,
  error,
  onRetry,
  onFilter,
}: {
  networks: AssetNetworkCount[]
  /** There are more networks than are listed. */
  capped: boolean
  isLoading: boolean
  error?: unknown
  onRetry: () => void
  onFilter: (network: string) => void
}) {
  const { t } = useTranslation()
  if (error) {
    return (
      <ErrorState
        title={t('assets.ip.networksError', 'networks')}
        error={error}
        onRetry={onRetry}
      />
    )
  }
  if (isLoading) {
    return (
      <div className="space-y-2 p-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    )
  }
  if (networks.length === 0) {
    return (
      <EmptyState
        card={false}
        icon={Network}
        title={t('assets.ip.networksEmpty', 'No networks match')}
        description={t(
          'assets.ip.networksEmptyHint',
          'Only IP addresses are grouped by network. Try removing a filter.'
        )}
      />
    )
  }
  return (
    <div data-testid="inventory-networks">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t('assets.ip.network', 'Network /24')}</TableHead>
            <TableHead className="text-end">{t('assets.ip.addresses', 'Addresses')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {networks.map((n) => {
            const cidr = networkFilter(n.network)
            const label = toDisplayText(n.network, 64)
            return (
              <TableRow key={n.network}>
                <TableCell>
                  {cidr ? (
                    <button
                      type="button"
                      className="rounded font-mono text-sm underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      dir="ltr"
                      title={t('assets.ip.filterNetwork', 'Show only {network}', {
                        network: label,
                      })}
                      onClick={() => onFilter(cidr)}
                    >
                      {label}
                    </button>
                  ) : (
                    <span className="font-mono text-sm" dir="ltr">
                      {label}
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-end tabular-nums">{n.count.toLocaleString()}</TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
      {capped && (
        <p className="px-3 py-2 text-xs text-muted-foreground" role="status">
          {t(
            'assets.ip.networksCapped',
            'Showing the {count} networks with the most addresses. Narrow the filter to see the rest.',
            { count: networks.length.toLocaleString() }
          )}
        </p>
      )}
    </div>
  )
}
