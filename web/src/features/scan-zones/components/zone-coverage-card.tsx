'use client'

import { useMemo } from 'react'
import Link from '@/components/link'
import useSWR from 'swr'
import { ArrowUpRight, CheckCircle2 } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { fetchAllPages } from '@/lib/api/fetch-all-pages'
import { API_BASE } from '@/lib/api/endpoints'
import type { ScanZone, ScanZoneCoverage } from '@/lib/api/scan-zone-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import { isPrivatePrefix, parsePrefix, prefixContainsAddr } from '../lib/ranges'

interface InventoryAsset {
  id: string
  name: string
  type: string
}

/** Asset types whose name can be one IP address, as the coverage endpoint counts them. */
const ADDRESS_TYPES = 'ip_address,host'
const PER_PAGE = 100
/** Bound the browser-side listing; the counts above always come from the API. */
const MAX_PAGES = 10
const MAX_LISTED = 50

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
    async () => {
      let truncated = false
      const rows = await fetchAllPages<InventoryAsset>(
        (page, perPage) =>
          `${API_BASE.ASSETS}?types=${ADDRESS_TYPES}&page=${page}&per_page=${perPage}`,
        {
          perPage: PER_PAGE,
          maxPages: MAX_PAGES,
          onTruncated: () => {
            truncated = true
          },
        }
      )
      return { rows, truncated }
    },
    { revalidateOnFocus: false }
  )
}

interface ZoneCoverageCardProps {
  coverage: ScanZoneCoverage
  zones: ScanZone[]
}

/**
 * RFC-023 V3: which inventory addresses fall in no zone, and which zones with
 * private ranges have no healthy sensor. Counts are the API's; the address
 * list is computed in the browser from the inventory (first 1,000 addresses).
 */
export function ZoneCoverageCard({ coverage, zones }: ZoneCoverageCardProps) {
  const { t } = useTranslation()
  const outside = coverage.outside_private + coverage.outside_public
  // Listing the addresses reads the asset inventory; without assets:read only
  // the API's counts are shown.
  const canReadAssets = useHasPermission(Permission.AssetsRead)
  const { data, isLoading, error } = useInventoryAddresses(outside > 0 && canReadAssets)
  const listed = useMemo(() => (data ? addressesOutsideZones(data.rows, zones) : []), [data, zones])

  const unhealthyPrivate = coverage.zones.filter(
    (z) => (z.has_private_range || z.is_default) && z.healthy_sensors === 0
  )

  return (
    <Card data-testid="zone-coverage">
      <CardHeader>
        <CardTitle>{t('scans.zones.coverage.title')}</CardTitle>
        <CardDescription>
          {t(
            coverage.has_default_zone
              ? 'scans.zones.coverage.descDefault'
              : 'scans.zones.coverage.desc',
            undefined,
            {
              total: coverage.inventory_addresses.toLocaleString(),
              inside: coverage.in_zones.toLocaleString(),
              private: coverage.outside_private.toLocaleString(),
              public: coverage.outside_public.toLocaleString(),
            }
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section aria-labelledby="zone-outside-heading" className="min-w-0 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <h3 id="zone-outside-heading" className="text-sm font-semibold">
              {t('scans.zones.coverage.outsideHeading')}
            </h3>
            {canReadAssets && (
              <Button asChild variant="link" size="sm" className="h-auto p-0">
                <Link href="/assets?types=ip_address">
                  {t('scans.zones.coverage.assetInventory')}
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </Link>
              </Button>
            )}
          </div>
          {outside === 0 ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <CheckCircle2 className="h-4 w-4 text-success" />
              {t('scans.zones.coverage.allInside')}
            </p>
          ) : !canReadAssets ? (
            <p className="text-sm text-muted-foreground">
              {t('scans.zones.coverage.noAssetsAccess', undefined, {
                count: outside.toLocaleString(),
              })}
            </p>
          ) : isLoading ? (
            <div className="space-y-1.5">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-7 w-full" />
              ))}
            </div>
          ) : error ? (
            <p className="text-sm text-muted-foreground">
              {t('scans.zones.coverage.listFailed', undefined, { count: outside.toLocaleString() })}
            </p>
          ) : (
            <>
              <ul className="divide-y rounded-md border" data-testid="zone-outside-list">
                {listed.slice(0, MAX_LISTED).map((a) => (
                  <li key={a.id} className="flex items-center justify-between gap-2 px-3 py-1.5">
                    <Link
                      href={`/assets/${a.id}`}
                      className="min-w-0 truncate font-mono text-sm hover:underline"
                    >
                      {a.address}
                    </Link>
                    {a.private ? (
                      <Badge
                        variant="outline"
                        className="shrink-0 text-xs font-normal text-warning"
                      >
                        {t('scans.zones.coverage.privateNotScanned')}
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="shrink-0 text-xs font-normal">
                        {t('scans.zones.coverage.public')}
                      </Badge>
                    )}
                  </li>
                ))}
              </ul>
              <p className="text-xs text-muted-foreground">
                {listed.length > MAX_LISTED
                  ? t('scans.zones.coverage.showing', undefined, {
                      shown: MAX_LISTED,
                      total: listed.length,
                    }) + ' '
                  : ''}
                {data?.truncated
                  ? t('scans.zones.coverage.truncated', undefined, {
                      count: (PER_PAGE * MAX_PAGES).toLocaleString(),
                    })
                  : t('scans.zones.coverage.addRanges')}
              </p>
            </>
          )}
        </section>

        <section aria-labelledby="zone-unhealthy-heading" className="min-w-0 space-y-2">
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
                <li key={z.zone_id} className="flex items-center justify-between gap-2 px-3 py-1.5">
                  <span className="min-w-0 truncate text-sm font-medium">{z.name}</span>
                  <span className="shrink-0 text-xs text-destructive">
                    {z.assigned_sensors === 0
                      ? t('scans.zones.noSensorsAssigned')
                      : t('scans.zones.coverage.zeroOnline', undefined, {
                          assigned: z.assigned_sensors,
                        })}
                    {z.addresses > 0
                      ? t('scans.zones.coverage.addressesWait', undefined, {
                          count: z.addresses.toLocaleString(),
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
