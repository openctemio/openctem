'use client'

/**
 * Addresses of a name (research/531): what its DNS answers hold now, grouped
 * by the provider whose shared range holds them, with the full history (first
 * seen, last seen, removed) one step away in a dialog. An address inside a
 * range a provider publishes for infrastructure many organizations share is
 * recorded only here, never as an address asset. Hidden when the caller may
 * not read the name (the API's own refusal).
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { History, Network } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable, EmptyState, RelativeTime } from '@/features/shared'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import { FactChip, ChipMono } from './service-cells/fact-chip'
import {
  currentAddressGroups,
  useNameAddresses,
  type NameAddress,
} from '../hooks/use-name-addresses'

/** Addresses shown per group before "+N more" (the rest are in History). */
const SHOWN_PER_GROUP = 8

export function NameAddressesSection({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading } = useNameAddresses(assetId)
  const [historyOpen, setHistoryOpen] = useState(false)
  useSettleSignal(isLoading)

  const groups = useMemo(() => currentAddressGroups(data?.items ?? []), [data])

  // A refusal (no permission, out of scope) hides the section.
  if (error) return null

  const total = data?.items.length ?? 0
  return (
    <Card id="asset-addresses">
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
        <CardTitle>{t('assetAddresses.title', 'Addresses')}</CardTitle>
        {total > 0 && (
          <Button variant="outline" size="sm" onClick={() => setHistoryOpen(true)}>
            <History className="h-4 w-4" />
            {t('assetAddresses.history', 'History')}
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading || !data ? (
          <Skeleton className="h-16 w-full" />
        ) : groups.length === 0 ? (
          <EmptyState
            icon={Network}
            card={false}
            title={t('assetAddresses.emptyTitle', 'No current addresses')}
            description={
              total > 0
                ? t(
                    'assetAddresses.emptyPast',
                    'This name resolves to none of the addresses it had. History lists them.'
                  )
                : t('assetAddresses.emptyHint', 'No DNS answer for this name is on record yet.')
            }
          />
        ) : (
          <ul className="space-y-3" data-testid="name-address-groups">
            {groups.map((g) => (
              <li key={g.provider || '-'} className="space-y-1.5">
                <p className="text-sm font-medium">
                  {g.provider
                    ? t('assetAddresses.servedBy', 'Served by {provider}', { provider: g.provider })
                    : t('assetAddresses.other', 'Other addresses')}
                  <span className="ml-2 text-xs font-normal text-muted-foreground tabular-nums">
                    {t(
                      'assetAddresses.count',
                      '{count, plural, one {# address} other {# addresses}}',
                      { count: g.addresses.length }
                    )}
                  </span>
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {g.addresses.slice(0, SHOWN_PER_GROUP).map((a) => (
                    <FactChip key={a} tone="muted">
                      <ChipMono>{a}</ChipMono>
                    </FactChip>
                  ))}
                  {g.addresses.length > SHOWN_PER_GROUP && (
                    <button
                      type="button"
                      className="text-xs text-muted-foreground underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      onClick={() => setHistoryOpen(true)}
                    >
                      {t('assetAddresses.more', '+{count} more', {
                        count: g.addresses.length - SHOWN_PER_GROUP,
                      })}
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
        {groups.some((g) => g.provider) && (
          <p className="text-xs text-muted-foreground">
            {t(
              'assetAddresses.providerHint',
              'Addresses a provider shares with many organizations are recorded on this name, not as your assets. Scans test this name, not those addresses.'
            )}
          </p>
        )}
      </CardContent>
      {data && (
        <AddressHistoryDialog
          open={historyOpen}
          onOpenChange={setHistoryOpen}
          items={data.items}
          truncated={data.truncated}
        />
      )}
    </Card>
  )
}

function AddressHistoryDialog({
  open,
  onOpenChange,
  items,
  truncated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  items: NameAddress[]
  truncated: number
}) {
  const { t } = useTranslation()
  const columns = useMemo<ColumnDef<NameAddress>[]>(
    () => [
      {
        id: 'address',
        header: t('assetAddresses.col.address', 'Address'),
        cell: ({ row }) => (
          <span className="font-mono text-sm break-all">{row.original.address}</span>
        ),
      },
      {
        id: 'provider',
        header: t('assetAddresses.col.provider', 'Provider'),
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">{row.original.provider ?? ''}</span>
        ),
      },
      {
        id: 'firstSeen',
        header: t('assetAddresses.col.firstSeen', 'First seen'),
        cell: ({ row }) => (
          <RelativeTime date={row.original.first_seen} className="text-sm text-muted-foreground" />
        ),
      },
      {
        id: 'lastSeen',
        header: t('assetAddresses.col.lastSeen', 'Last seen'),
        cell: ({ row }) => (
          <RelativeTime date={row.original.last_seen} className="text-sm text-muted-foreground" />
        ),
      },
      {
        id: 'state',
        header: t('assetAddresses.col.state', 'Now'),
        cell: ({ row }) =>
          row.original.current ? (
            <span className="text-sm">{t('assetAddresses.current', 'Current')}</span>
          ) : (
            <span className="text-sm text-muted-foreground">
              {t('assetAddresses.gone', 'No longer resolves')}
            </span>
          ),
      },
    ],
    [t]
  )
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('assetAddresses.historyTitle', 'Address history')}</DialogTitle>
          <DialogDescription>
            {t(
              'assetAddresses.historyHint',
              'Every address this name resolved to, with when it was first and last seen.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <DataTable
            columns={columns}
            data={items}
            getRowId={(a) => a.address}
            // Opened only once the list is loaded; a failed read hides the card.
            error={null}
            showSearch={items.length > 10}
            showColumnToggle={false}
            showPagination={items.length > 20}
          />
          {truncated > 0 && (
            <p className="mt-2 text-sm text-muted-foreground" role="status">
              {t('assetAddresses.truncated', '{count} older addresses are not listed.', {
                count: truncated.toLocaleString(),
              })}
            </p>
          )}
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}
