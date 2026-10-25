'use client'

import { useState } from 'react'
import { ChevronLeft, ChevronRight, Crown, Globe, Server } from 'lucide-react'
import { SignalChip } from '@/components/ui/signal-chip'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { PriorityBadge } from '@/components/ui/priority-badge'
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
import { ErrorState } from '@/features/shared/components/error-state'
import { ListToolbar } from '@/features/shared/components/list-toolbar'
import { useSearchQuery } from '@/hooks/use-search-query'
import { cn } from '@/lib/utils'
import { useCveExposureAssets } from '../../api/use-cve-exposure'
import type { CveExposureAsset } from '../../types/exposure'
import { cveFindingsHref } from '../../lib/vuln-page'

const PER_PAGE = 10

/**
 * "Where": the assets with a finding of the CVE in the caller's scope, with
 * their exposure context, owner, open findings and worst priority. Server
 * paged and searched; assets outside the scope are neither shown nor counted.
 */
export function WhereCard({ cve, impacted }: { cve: string; impacted: number }) {
  const { t } = useTranslation()
  const [input, setInput] = useState('')
  const [page, setPage] = useState(1)
  const { term } = useSearchQuery(input)
  const { data, error, isLoading, mutate } = useCveExposureAssets(cve, {
    q: term || undefined,
    page,
    perPage: PER_PAGE,
  })
  const rows = data?.data ?? []
  const total = data?.total ?? 0
  const pages = Math.max(1, data?.total_pages ?? 1)

  return (
    <Card data-slot="where-card" className="min-w-0">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">
          {t('vulnPage.where.title', 'Where')}{' '}
          <span className="ms-1 rounded border px-1.5 py-0.5 text-xs font-medium tabular-nums text-muted-foreground">
            {total.toLocaleString()}
          </span>
        </CardTitle>
        <CardAction className="self-center">
          <Link
            href={cveFindingsHref(cve, { group: 'asset_id' })}
            className="text-xs text-muted-foreground hover:text-foreground hover:underline"
          >
            {t('vulnPage.where.all', 'All findings by asset')}
          </Link>
        </CardAction>
      </CardHeader>
      <CardContent className="space-y-3">
        <ListToolbar
          search={{
            value: input,
            onChange: (v) => {
              setInput(v)
              setPage(1)
            },
            placeholder: t('vulnPage.where.search', 'Search asset names…'),
            label: t('vulnPage.where.searchLabel', 'Search the affected assets by name'),
          }}
        />
        {error ? (
          <ErrorState
            title={t('vulnPage.where.subject', 'the affected assets')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading && !data ? (
          <div className="space-y-2" aria-busy>
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-8 text-center">
            <Server className="h-6 w-6 text-muted-foreground" aria-hidden />
            <p className="text-sm text-muted-foreground">
              {term
                ? t('vulnPage.where.noMatch', 'No affected asset matches "{term}".', { term })
                : impacted === 0
                  ? t(
                      'vulnPage.where.empty',
                      'No asset in your scope has a finding of this vulnerability.'
                    )
                  : t('vulnPage.where.emptyPage', 'No assets on this page.')}
            </p>
          </div>
        ) : (
          <div className="-mx-6 overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="ps-6">{t('vulnPage.where.col.asset', 'Asset')}</TableHead>
                  <TableHead>{t('vulnPage.where.col.exposure', 'Exposure')}</TableHead>
                  <TableHead className="hidden md:table-cell">
                    {t('vulnPage.where.col.owner', 'Owner')}
                  </TableHead>
                  <TableHead className="text-end">{t('vulnPage.where.col.open', 'Open')}</TableHead>
                  <TableHead className="pe-6">{t('vulnPage.where.col.worst', 'Worst')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((a) => (
                  <AssetRow key={a.asset_id} cve={cve} asset={a} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
      <CardFooter className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>
          {t('vulnPage.where.scopeNote', 'Assets outside your scope are not shown or counted.')}
        </span>
        {pages > 1 && (
          <span className="flex items-center gap-1">
            <span className="me-1 tabular-nums">
              {t('vulnPage.where.page', 'Page {page} of {pages}', { page, pages })}
            </span>
            <Button
              variant="outline"
              size="icon"
              className="h-7 w-7"
              aria-label={t('vulnPage.where.prev', 'Previous page')}
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeft className="h-4 w-4 rtl:rotate-180" aria-hidden />
            </Button>
            <Button
              variant="outline"
              size="icon"
              className="h-7 w-7"
              aria-label={t('vulnPage.where.next', 'Next page')}
              disabled={page >= pages}
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
            >
              <ChevronRight className="h-4 w-4 rtl:rotate-180" aria-hidden />
            </Button>
          </span>
        )}
      </CardFooter>
    </Card>
  )
}

function AssetRow({ cve, asset }: { cve: string; asset: CveExposureAsset }) {
  const { t } = useTranslation()
  const closed = asset.open_findings === 0
  return (
    <TableRow data-slot="where-row" className={cn(closed && 'text-muted-foreground')}>
      <TableCell className="max-w-[16rem] ps-6">
        <Link
          href={`/assets/${encodeURIComponent(asset.asset_id)}`}
          className="block truncate font-medium hover:underline"
          title={asset.name}
        >
          {asset.name}
        </Link>
      </TableCell>
      <TableCell>
        <span className="flex flex-wrap items-center gap-1">
          {asset.crown_jewel && (
            <SignalChip icon={Crown}>{t('vulnPage.where.crown', 'Crown jewel')}</SignalChip>
          )}
          {asset.internet_facing && (
            <SignalChip
              icon={Globe}
              title={t('vulnPage.where.netTitle', 'Reachable from the internet')}
            >
              {t('vulnPage.where.net', 'Internet')}
            </SignalChip>
          )}
          {!asset.crown_jewel && !asset.internet_facing && (
            <span className="text-xs text-muted-foreground">
              {t('vulnPage.where.internal', 'Internal')}
            </span>
          )}
        </span>
      </TableCell>
      <TableCell className="hidden max-w-[12rem] truncate md:table-cell">
        {asset.owner || (
          <span className="text-muted-foreground">{t('vulnPage.where.noOwner', 'No owner')}</span>
        )}
      </TableCell>
      <TableCell className="text-end tabular-nums">
        <Link
          href={cveFindingsHref(cve, { asset_id: asset.asset_id, state: 'open' })}
          className="hover:underline"
        >
          {asset.open_findings.toLocaleString()}
        </Link>
      </TableCell>
      <TableCell className="pe-6">
        {asset.worst_priority ? (
          <PriorityBadge priorityClass={asset.worst_priority} />
        ) : (
          <span className="text-xs text-muted-foreground">
            {closed
              ? t('vulnPage.where.closed', 'All closed')
              : t('vulnPage.where.notPrioritized', 'Not prioritized')}
          </span>
        )}
      </TableCell>
    </TableRow>
  )
}
