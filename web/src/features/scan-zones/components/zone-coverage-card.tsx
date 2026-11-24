'use client'

import { useMemo } from 'react'
import Link from '@/components/link'
import useSWR from 'swr'
import { ArrowRight, CheckCircle2 } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { fetchAllPages } from '@/lib/api/fetch-all-pages'
import { API_BASE } from '@/lib/api/endpoints'
import type { ScanZone, ScanZoneCoverage } from '@/lib/api/scan-zone-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import { isPrivatePrefix, parsePrefix, prefixContainsAddr } from '../lib/ranges'
import { formatNumber } from '@/lib/app-locale'

interface InventoryAsset {
  id: string
  name: string
  type: string
}

/** Asset types whose name can be one IP address, as the coverage endpoint counts them. */
const ADDRESS_TYPES = 'ip_address,host'
const PER_PAGE = 100
/** Bound the browser-side listing; the counts always come from the API. */
const MAX_PAGES = 10
/**
 * A few examples, never the whole list: an inventory can hold hundreds of
 * addresses outside every zone, and the asset inventory is where they are
 * reviewed (the link under the examples).
 */
export const MAX_EXAMPLES = 5
/** The asset inventory, narrowed to the address types the coverage counts. */
export const ADDRESSES_HREF = `/assets?types=${ADDRESS_TYPES}`

export interface OutsideAddress {
  id: string
  address: string
  type: string
  private: boolean
}

/**
 * Inventory addresses no zone range holds (the default zone's "public"
 * catch-all does not count: these are addresses no range names).
 */
export function addressesOutsideZones(
  assets: InventoryAsset[],
  zones: Pick<ScanZone, 'ranges'>[]
): OutsideAddress[] {
  const prefixes = zones.flatMap((z) => z.ranges).flatMap((r) => parsePrefix(r) ?? [])
  const out: OutsideAddress[] = []
  for (const a of assets) {
    const p = parsePrefix(a.name)
    if (!p || p.bits !== (p.addr.v4 ? 32 : 128)) continue // not a single IP address
    if (prefixes.some((z) => prefixContainsAddr(z, p.addr))) continue
    out.push({ id: a.id, address: a.name, type: a.type, private: isPrivatePrefix(p) })
  }
  // Private first: scans skip those (they need a zone); public go to the default zone.
  return out.sort((x, y) => Number(y.private) - Number(x.private))
}

function useInventoryAddresses(enabled: boolean) {
  return useSWR(
    enabled ? ['scan-zone-coverage-inventory', ADDRESS_TYPES] : null,
    async () => ({
      rows: await fetchAllPages<InventoryAsset>(
        (page, perPage) =>
          `${API_BASE.ASSETS}?types=${ADDRESS_TYPES}&page=${page}&per_page=${perPage}`,
        { perPage: PER_PAGE, maxPages: MAX_PAGES }
      ),
    }),
    { revalidateOnFocus: false }
  )
}

interface ZoneCoverageCardProps {
  coverage: ScanZoneCoverage
  zones: ScanZone[]
}

/** One labelled number: the label, then the figure. */
function Figure({ label, value, tone }: { label: string; value: number; tone?: 'warning' }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <dt className="text-muted-foreground">{label}</dt>
      <dd
        className={
          tone === 'warning' && value > 0
            ? 'font-semibold tabular-nums text-warning'
            : 'font-semibold tabular-nums'
        }
      >
        {formatNumber(value)}
      </dd>
    </div>
  )
}

/**
 * RFC-023 V3: which inventory addresses fall in no zone, and which zones with
 * private ranges have no healthy sensor. The counts are the API's (the strip
 * above the zones list carries the totals and "inside a zone"); this card
 * splits the addresses outside every zone into private and public, shows a
 * few examples (private first, computed in the browser from the first 1,000
 * inventory addresses) and links to the asset inventory for the rest.
 */
export function ZoneCoverageCard({ coverage, zones }: ZoneCoverageCardProps) {
  const { t } = useTranslation()
  const outside = coverage.outside_private + coverage.outside_public
  // The examples read the asset inventory; without assets:read only the
  // API's counts are shown.
  const canReadAssets = useHasPermission(Permission.AssetsRead)
  const { data, isLoading, error } = useInventoryAddresses(outside > 0 && canReadAssets)
  const examples = useMemo(
    () => (data ? addressesOutsideZones(data.rows, zones).slice(0, MAX_EXAMPLES) : []),
    [data, zones]
  )

  const unhealthyPrivate = coverage.zones.filter(
    (z) => (z.has_private_range || z.is_default) && z.healthy_sensors === 0
  )

  return (
    <Card data-testid="zone-coverage">
      <CardHeader>
        <CardTitle>{t('scans.zones.coverage.title')}</CardTitle>
      </CardHeader>
      <CardContent className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section aria-labelledby="zone-outside-heading" className="min-w-0 space-y-3">
          <h3 id="zone-outside-heading" className="text-sm font-semibold">
            {t('scans.zones.coverage.outsideHeading')}
          </h3>
          {outside === 0 ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <CheckCircle2 className="h-4 w-4 text-success" />
              {t('scans.zones.coverage.allInside')}
            </p>
          ) : (
            <>
              <dl
                className="flex flex-wrap gap-x-6 gap-y-1 text-sm"
                data-testid="zone-outside-counts"
              >
                <Figure
                  label={t('scans.zones.coverage.outsidePrivate')}
                  value={coverage.outside_private}
                  tone="warning"
                />
                <Figure
                  label={t(
                    coverage.has_default_zone
                      ? 'scans.zones.coverage.outsidePublicDefault'
                      : 'scans.zones.coverage.outsidePublic'
                  )}
                  value={coverage.outside_public}
                />
              </dl>
              {!canReadAssets ? (
                <p className="text-sm text-muted-foreground">
                  {t('scans.zones.coverage.noAssetsAccess', undefined, {
                    count: formatNumber(outside),
                  })}
                </p>
              ) : isLoading ? (
                <div className="flex flex-wrap gap-2">
                  {[0, 1, 2].map((i) => (
                    <Skeleton key={i} className="h-7 w-28" />
                  ))}
                </div>
              ) : error ? (
                <p className="text-sm text-muted-foreground">
                  {t('scans.zones.coverage.listFailed', undefined, {
                    count: formatNumber(outside),
                  })}
                </p>
              ) : (
                examples.length > 0 && (
                  <ul
                    className="flex flex-wrap gap-2"
                    data-testid="zone-outside-list"
                    aria-label={t('scans.zones.coverage.examples')}
                  >
                    {examples.map((a) => (
                      <li key={a.id} className="min-w-0 max-w-full">
                        <Link
                          href={`/assets/${a.id}`}
                          className="flex min-w-0 items-baseline gap-1.5 rounded-md border px-2 py-1 font-mono text-xs hover:bg-muted"
                        >
                          <span className="truncate">{a.address}</span>
                          {a.private && (
                            <span className="shrink-0 font-sans text-warning">
                              {t('scans.zones.coverage.privateTag')}
                            </span>
                          )}
                        </Link>
                      </li>
                    ))}
                  </ul>
                )
              )}
              {canReadAssets && (
                <Button asChild variant="link" size="sm" className="h-auto p-0">
                  <Link href={ADDRESSES_HREF} data-testid="zone-outside-all">
                    {t('scans.zones.coverage.viewAll', undefined, {
                      count: formatNumber(coverage.inventory_addresses),
                    })}
                    <ArrowRight className="h-3.5 w-3.5" aria-hidden />
                  </Link>
                </Button>
              )}
              {coverage.outside_private > 0 && (
                <p className="text-xs text-muted-foreground">
                  {t('scans.zones.coverage.addRanges')}
                </p>
              )}
            </>
          )}
        </section>

        <section aria-labelledby="zone-unhealthy-heading" className="min-w-0 space-y-3">
          <h3 id="zone-unhealthy-heading" className="text-sm font-semibold">
            {t('scans.zones.coverage.unhealthyHeading')}
          </h3>
          {unhealthyPrivate.length === 0 ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <CheckCircle2 className="h-4 w-4 text-success" />
              {t('scans.zones.coverage.allHealthy')}
            </p>
          ) : (
            <ul className="divide-y rounded-md border" data-testid="zone-unhealthy-list">
              {unhealthyPrivate.map((z) => (
                <li
                  key={z.zone_id}
                  className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 px-3 py-1.5"
                >
                  <span className="min-w-0 truncate text-sm font-medium">{z.name}</span>
                  <span className="text-xs text-destructive">
                    {z.assigned_sensors === 0
                      ? t('scans.zones.noSensorsAssigned')
                      : t('scans.zones.coverage.zeroOnline', undefined, {
                          assigned: z.assigned_sensors,
                        })}
                    {z.addresses > 0
                      ? t('scans.zones.coverage.addressesWait', undefined, {
                          count: formatNumber(z.addresses),
                        })
                      : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </CardContent>
    </Card>
  )
}
