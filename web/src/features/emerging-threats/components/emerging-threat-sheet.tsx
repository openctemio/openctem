'use client'

/**
 * The emerging-threat drawer (research/463 D8): opened from a list row, it
 * answers "why is it ranked here, what does it affect, what do I do" and
 * holds every action. The full page stays one click away. Server text
 * (product, version, asset names, description) is rendered as plain text.
 */

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import { Siren } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { formatEpssScore } from '@/lib/epss'
import { formatLocalized } from '@/lib/format-date'
import {
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
  DetailSheetHeader,
  DetailStat,
  DetailStatGrid,
  type DetailCalloutTone,
} from '@/features/shared/components/detail-sheet'
import { ErrorState } from '@/features/shared/components/error-state'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { SheetDetailToolbar } from '@/features/shared/components/sheet-detail-toolbar'
import { useEmergingThreat } from '../api'
import type { EmergingThreatAsset, EmergingThreatDetail, RecommendedAction } from '../types'
import { AlertActions, OutOfScopeHint, TaskCoverageNote } from './alert-actions'
import {
  EtsBreakdownList,
  ExploitBadges,
  LevelBadge,
  StateBadge,
  useEventDetail,
  useEventKindLabel,
} from './bits'

const TOP_ASSETS = 5
const TOP_EVENTS = 5

const ACTION_TONE: Record<RecommendedAction, DetailCalloutTone> = {
  patch_now: 'destructive',
  confirm: 'warning',
  patch_within_sla: 'info',
}

const CRITICALITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

/** Crown jewels first, then internet-facing, then confirmed before possible. */
export function rankAssets(assets: EmergingThreatAsset[]): EmergingThreatAsset[] {
  const tier = (a: EmergingThreatAsset) => (a.tier === 'possible' ? 1 : 0)
  return [...assets].sort(
    (a, b) =>
      (CRITICALITY_RANK[a.criticality] ?? 4) - (CRITICALITY_RANK[b.criticality] ?? 4) ||
      Number(b.internet_facing) - Number(a.internet_facing) ||
      tier(a) - tier(b) ||
      a.asset_name.localeCompare(b.asset_name)
  )
}

export interface ProductVersions {
  product: string
  /** Version seen to the number of assets running it; '' is "version unknown". */
  versions: { version: string; assets: number }[]
}

/** The affected assets grouped by product, then by the version seen. */
export function groupByProduct(assets: EmergingThreatAsset[]): ProductVersions[] {
  const byProduct = new Map<string, Map<string, Set<string>>>()
  for (const a of assets) {
    const product = a.product.trim()
    if (!product) continue
    const versions = byProduct.get(product) ?? new Map<string, Set<string>>()
    const ids = versions.get(a.version_seen) ?? new Set<string>()
    ids.add(a.asset_id)
    versions.set(a.version_seen, ids)
    byProduct.set(product, versions)
  }
  return [...byProduct.entries()]
    .map(([product, versions]) => ({
      product,
      versions: [...versions.entries()]
        .map(([version, ids]) => ({ version, assets: ids.size }))
        // Known versions first, most assets first.
        .sort((x, y) => Number(!x.version) - Number(!y.version) || y.assets - x.assets),
    }))
    .sort(
      (x, y) =>
        y.versions.reduce((n, v) => n + v.assets, 0) - x.versions.reduce((n, v) => n + v.assets, 0)
    )
}

export function EmergingThreatSheet({
  alertId,
  onClose,
}: {
  alertId: string | null
  onClose: () => void
}) {
  const { t } = useTranslation()
  const router = useRouter()
  const { data, error, isLoading, mutate } = useEmergingThreat(alertId ?? undefined)
  const fullPage = alertId ? `/emerging-threats/${alertId}` : ''
  return (
    <Sheet open={alertId !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent
        side="right"
        showCloseButton={false}
        className="w-full sm:max-w-xl"
        data-testid="emerging-threat-sheet"
      >
        <SheetHeader className="block p-0 sm:p-0">
          <SheetTitle className="sr-only">
            {data?.vuln_id ?? t('emergingThreats.sheet.title')}
          </SheetTitle>
          <SheetDescription className="sr-only">
            {t('emergingThreats.sheet.description')}
          </SheetDescription>
          <SheetDetailToolbar
            title={t('emergingThreats.sheet.title')}
            onClose={onClose}
            onOpenExternal={fullPage ? () => router.push(fullPage) : undefined}
          />
        </SheetHeader>
        <SheetBody className="p-0">
          {error ? (
            <div className="p-4 sm:p-6">
              <ErrorState
                title={t('emergingThreats.loadOneError')}
                error={error}
                onRetry={() => void mutate()}
              />
            </div>
          ) : isLoading || !data || data.id !== alertId ? (
            <div className="space-y-4 p-4 sm:p-6">
              <Skeleton className="h-10 w-2/3" />
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-48 w-full" />
            </div>
          ) : (
            <SheetBodyContent alert={data} fullPage={fullPage} />
          )}
        </SheetBody>
      </SheetContent>
    </Sheet>
  )
}

function SheetBodyContent({ alert, fullPage }: { alert: EmergingThreatDetail; fullPage: string }) {
  const { t, locale } = useTranslation()
  const kindLabel = useEventKindLabel()
  const detailOf = useEventDetail()
  const products = useMemo(() => groupByProduct(alert.assets), [alert.assets])
  const top = useMemo(() => rankAssets(alert.assets).slice(0, TOP_ASSETS), [alert.assets])
  const more = Math.max(0, alert.product_count - 1)
  const b = alert.ets_breakdown

  return (
    <>
      <DetailSheetHeader
        icon={Siren}
        title={<span className="font-mono">{alert.vuln_id}</span>}
        subtitle={
          alert.product
            ? more > 0
              ? `${alert.product} ${t('emergingThreats.threat.moreProducts', undefined, { n: more })}`
              : alert.product
            : undefined
        }
        status={<StateBadge state={alert.state} />}
        badges={
          <>
            <LevelBadge level={alert.level} />
            <ExploitBadges
              inKev={alert.in_kev}
              ransomware={alert.kev_ransomware}
              epss={alert.epss}
            />
          </>
        }
        actions={<AlertActions alert={alert} />}
      />
      <div className="space-y-4 px-4 pb-5 sm:px-6">
        <OutOfScopeHint alert={alert} />
        <TaskCoverageNote alert={alert} />
        <DetailCallout
          tone={ACTION_TONE[alert.recommended_action] ?? 'info'}
          title={t(`emergingThreats.action.${alert.recommended_action}`)}
        />

        <DetailStatGrid>
          <DetailStat
            label={t('emergingThreats.sheet.statScore')}
            value={Math.round(alert.ets)}
            unit={t('emergingThreats.sheet.outOf')}
            meter={{
              value: alert.ets,
              max: 100,
              label: t('emergingThreats.ets.meter', undefined, { n: Math.round(alert.ets) }),
            }}
          />
          <DetailStat
            label={t('emergingThreats.sheet.statAffected')}
            value={alert.confirmed_assets}
            caption={
              alert.possible_assets > 0
                ? t('emergingThreats.sheet.possibleCaption', undefined, {
                    n: alert.possible_assets,
                  })
                : undefined
            }
          />
          <DetailStat
            label={t('emergingThreats.sheet.statInternet')}
            value={alert.internet_facing_assets}
            tone={alert.internet_facing_assets > 0 ? 'warning' : 'default'}
          />
          <DetailStat
            label={t('emergingThreats.sheet.statCritical')}
            value={alert.critical_assets}
            tone={alert.critical_assets > 0 ? 'destructive' : 'default'}
          />
        </DetailStatGrid>
      </div>
      <DetailSections className="px-4 pb-6 sm:px-6">
        <DetailSection title={t('emergingThreats.sheet.why')}>
          <p className="mb-2 text-sm text-muted-foreground">
            {t('emergingThreats.detail.scoreHint')}
          </p>
          <EtsBreakdownList breakdown={b} />
        </DetailSection>

        <DetailSection title={t('emergingThreats.sheet.exploit')}>
          <DetailFieldGrid>
            <DetailField label={t('emergingThreats.detail.kev')}>
              {alert.in_kev
                ? alert.kev_date_added
                  ? t('emergingThreats.detail.kevAdded', undefined, { date: alert.kev_date_added })
                  : t('emergingThreats.detail.yes')
                : t('emergingThreats.detail.no')}
            </DetailField>
            <DetailField label={t('emergingThreats.detail.ransomware')}>
              {alert.kev_ransomware
                ? t('emergingThreats.detail.yes')
                : t('emergingThreats.detail.no')}
            </DetailField>
            <DetailField label={t('emergingThreats.detail.epss')}>
              {alert.epss != null
                ? formatEpssScore(alert.epss, 1)
                : t('emergingThreats.detail.unknown')}
            </DetailField>
            <DetailField label={t('emergingThreats.detail.cvss')}>
              {alert.cvss_score != null
                ? String(alert.cvss_score)
                : t('emergingThreats.detail.unknown')}
            </DetailField>
            <DetailField label={t('emergingThreats.detail.severity')}>
              {alert.severity
                ? t(`severity.${alert.severity}`, alert.severity)
                : t('emergingThreats.detail.unknown')}
            </DetailField>
            <DetailField label={t('emergingThreats.sheet.disclosed')}>
              {alert.published_at ? (
                <span className="inline-flex flex-wrap items-baseline gap-x-2">
                  <span>{formatLocalized(alert.published_at, locale)}</span>
                  <RelativeTime date={alert.published_at} className="text-muted-foreground" />
                </span>
              ) : (
                t('emergingThreats.detail.unknown')
              )}
            </DetailField>
          </DetailFieldGrid>
        </DetailSection>

        {products.length > 0 && (
          <DetailSection title={t('emergingThreats.sheet.products')} count={products.length}>
            <ul className="space-y-2 text-sm" data-testid="et-products">
              {products.map((p) => (
                <li key={p.product} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="min-w-0 truncate font-medium">{p.product}</span>
                  {p.versions.map((v) => (
                    <span key={v.version || '-'} className="inline-flex items-center gap-1.5">
                      <span className={v.version ? 'font-mono' : 'text-muted-foreground'}>
                        {v.version || t('emergingThreats.sheet.versionUnknown')}
                      </span>
                      <span className="text-muted-foreground tabular-nums">
                        {t('emergingThreats.sheet.assetsOn', undefined, { n: v.assets })}
                      </span>
                    </span>
                  ))}
                </li>
              ))}
            </ul>
          </DetailSection>
        )}

        <DetailSection
          title={t('emergingThreats.sheet.topAssets')}
          count={alert.assets.length}
          actions={
            alert.assets.length > TOP_ASSETS ? (
              <Link href={fullPage} className="text-sm hover:underline">
                {t('emergingThreats.sheet.viewAll')}
              </Link>
            ) : undefined
          }
        >
          {top.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('emergingThreats.assets.noneConfirmed')}
            </p>
          ) : (
            <ul className="divide-y text-sm">
              {top.map((a) => (
                <li
                  key={`${a.asset_id}-${a.product}-${a.version_seen}`}
                  className="flex items-center gap-3 py-2"
                >
                  <div className="min-w-0 flex-1">
                    <Link
                      href={`/assets/${a.asset_id}`}
                      className="block truncate font-medium hover:underline"
                    >
                      {a.asset_name}
                    </Link>
                    <p className="truncate text-muted-foreground">
                      {a.tier === 'possible'
                        ? t('emergingThreats.assets.possible')
                        : a.tier === 'likely'
                          ? t('emergingThreats.assets.likely')
                          : t('emergingThreats.tier.confirmed')}
                    </p>
                  </div>
                  <div className="flex shrink-0 flex-wrap items-center justify-end gap-1">
                    {a.criticality && (
                      <Badge variant="outline">
                        {t(`criticality.${a.criticality}`, a.criticality)}
                      </Badge>
                    )}
                    {a.internet_facing && (
                      <Badge variant="outline">{t('emergingThreats.assets.internetFacing')}</Badge>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </DetailSection>

        <DetailSection
          title={t('emergingThreats.sheet.timeline')}
          actions={
            alert.timeline.length > TOP_EVENTS ? (
              <Link href={fullPage} className="text-sm hover:underline">
                {t('emergingThreats.sheet.viewAll')}
              </Link>
            ) : undefined
          }
        >
          {alert.timeline.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('emergingThreats.detail.noEvents')}</p>
          ) : (
            <ol className="space-y-2 text-sm">
              {alert.timeline.slice(0, TOP_EVENTS).map((ev, i) => {
                const detail = detailOf(ev)
                return (
                  <li
                    key={`${ev.kind}-${ev.at}-${i}`}
                    className="flex items-baseline justify-between gap-3"
                  >
                    <span className="min-w-0">
                      <span className="font-medium">{kindLabel(ev.kind)}</span>
                      {detail && <span className="block text-muted-foreground">{detail}</span>}
                    </span>
                    <RelativeTime date={ev.at} className="shrink-0 text-muted-foreground" />
                  </li>
                )
              })}
            </ol>
          )}
        </DetailSection>
      </DetailSections>
    </>
  )
}
