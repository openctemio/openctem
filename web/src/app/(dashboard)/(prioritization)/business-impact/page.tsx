'use client'

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  PageStack,
  EmptyState,
  MetricStrip,
  RiskScoreBadge,
  DataTable,
  DataTableColumnHeader,
} from '@/features/shared'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import { Building2, Crown } from 'lucide-react'
import { useTenant } from '@/context/tenant-provider'
import { useDashboardStats } from '@/features/dashboard/hooks/use-dashboard-stats'
import { useAssetStats } from '@/features/assets/hooks/use-assets'
import {
  useBusinessUnits,
  type BusinessUnit,
} from '@/features/business-units/api/use-business-units'
import { useCrownJewels } from '@/features/crown-jewels/api/use-crown-jewels'
import { CRITICALITY_DOT_COLORS } from '@/lib/criticality-colors'
import { ASSET_CRITICALITY_LEVELS, CRITICALITY_LABELS } from '@/lib/criticality'

type TFn = ReturnType<typeof useTranslation>['t']

function buildColumns(t: TFn): ColumnDef<BusinessUnit>[] {
  return [
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('prioritization.businessImpact.col.unit', 'Business unit')}
        />
      ),
      cell: ({ row }) => (
        <div className="min-w-0">
          <span className="font-medium">{row.original.name}</span>
          {row.original.description && (
            <p className="line-clamp-1 text-xs text-muted-foreground">{row.original.description}</p>
          )}
        </div>
      ),
    },
    {
      accessorKey: 'owner_name',
      header: t('prioritization.businessImpact.col.owner', 'Owner'),
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{row.original.owner_name || '—'}</span>
      ),
    },
    {
      accessorKey: 'asset_count',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('prioritization.businessImpact.col.assets', 'Assets')}
        />
      ),
      cell: ({ row }) => <span className="tabular-nums">{row.original.asset_count}</span>,
    },
    {
      accessorKey: 'critical_finding_count',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('prioritization.businessImpact.col.critical', 'Critical findings')}
        />
      ),
      cell: ({ row }) => {
        const n = row.original.critical_finding_count
        return (
          <span className={n > 0 ? 'font-medium tabular-nums text-destructive' : 'tabular-nums'}>
            {n}
          </span>
        )
      },
    },
    {
      accessorKey: 'finding_count',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('prioritization.businessImpact.col.findings', 'Findings')}
        />
      ),
      cell: ({ row }) => <span className="tabular-nums">{row.original.finding_count}</span>,
    },
    {
      accessorKey: 'avg_risk_score',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('prioritization.businessImpact.col.risk', 'Avg risk')}
        />
      ),
      cell: ({ row }) => (
        <RiskScoreBadge score={Number((row.original.avg_risk_score || 0).toFixed(1))} size="sm" />
      ),
    },
  ]
}

export default function BusinessImpactPage() {
  const { t } = useTranslation()
  const buColumns = useMemo(() => buildColumns(t), [t])
  const { currentTenant } = useTenant()
  const { stats, isLoading: statsLoading } = useDashboardStats(currentTenant?.id || null)
  const { stats: assetStats, isLoading: assetStatsLoading } = useAssetStats()
  const { data: buData, isLoading: buLoading } = useBusinessUnits()
  const { data: crownData, isLoading: crownLoading } = useCrownJewels()

  const isLoading = statsLoading || assetStatsLoading || buLoading || crownLoading

  // Derived metrics from real data
  const criticalFindings = stats.findings.bySeverity['critical'] || 0
  const highFindings = stats.findings.bySeverity['high'] || 0
  const criticalAssets = assetStats.byCriticality['critical'] || 0

  // Crown jewel assets sorted by risk score desc
  const topCrownJewels = useMemo(() => {
    const assets = (crownData?.data || []) as Array<{
      id: string
      name: string
      type: string
      risk_score?: number
      finding_count?: number
      criticality?: string
    }>
    return [...assets].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 5)
  }, [crownData])

  // Asset criticality breakdown — sorted critical→low, then Not rated
  const criticalityBreakdown = useMemo(() => {
    const total = assetStats.total || 1
    return ASSET_CRITICALITY_LEVELS.map((level) => {
      const count = assetStats.byCriticality[level] || 0
      return { level, count, percentage: Math.round((count / total) * 100) }
    })
  }, [assetStats])

  // Business units sorted by avg_risk_score desc
  const sortedUnits = useMemo(
    () =>
      [...(buData?.data || [])].sort((a, b) => (b.avg_risk_score || 0) - (a.avg_risk_score || 0)),
    [buData]
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('prioritization.businessImpact.title', 'Business impact')}
          description={t(
            'prioritization.businessImpact.description',
            'Where vulnerabilities hit the business hardest, by asset criticality, crown jewel and business unit.'
          )}
        />

        <MetricStrip
          loading={isLoading}
          items={[
            {
              key: 'assets',
              label: t('prioritization.businessImpact.stat.assets', 'Assets'),
              value: assetStats.total,
              hint: t('prioritization.businessImpact.stat.withFindings', '{count} with findings', {
                count: assetStats.withFindings,
              }),
              href: '/assets',
            },
            {
              key: 'critical',
              label: t('prioritization.businessImpact.stat.critical', 'Critical findings'),
              value: criticalFindings,
              tone: 'danger',
              hint: t('prioritization.businessImpact.stat.highSeverity', '{count} high severity', {
                count: highFindings,
              }),
              href: '/findings?severity=critical',
            },
            {
              key: 'criticalAssets',
              label: t('prioritization.businessImpact.stat.criticalAssets', 'Critical assets'),
              value: criticalAssets,
              hint: t(
                'prioritization.businessImpact.stat.highRisk',
                '{count} high-risk (score ≥ 70)',
                { count: assetStats.highRiskCount }
              ),
              href: '/assets?criticalities=critical',
            },
          ]}
        />

        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t('prioritization.businessImpact.criticality.title', 'Asset criticality')}
              </CardTitle>
              <CardDescription>
                {t(
                  'prioritization.businessImpact.criticality.description',
                  'How your assets spread across criticality levels.'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {assetStatsLoading
                ? Array.from({ length: 4 }).map((_, i) => (
                    <div key={i} className="space-y-2">
                      <Skeleton className="h-4 w-full" />
                      <Skeleton className="h-2 w-full" />
                    </div>
                  ))
                : criticalityBreakdown.map(({ level, count, percentage }) => (
                    <div key={level} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-2 text-sm font-medium">
                          <span
                            className={`size-2 shrink-0 rounded-full ${CRITICALITY_DOT_COLORS[level]}`}
                          />
                          {t(`criticality.${level}`, CRITICALITY_LABELS[level])}
                        </span>
                        <span className="text-sm font-semibold tabular-nums">
                          {count}{' '}
                          <span className="text-xs font-normal text-muted-foreground">
                            ({percentage}%)
                          </span>
                        </span>
                      </div>
                      <Progress value={percentage} className="h-2" />
                    </div>
                  ))}
            </CardContent>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-base">
                {t('prioritization.businessImpact.crown.title', 'Crown jewels')}
              </CardTitle>
              <CardDescription>
                {t(
                  'prioritization.businessImpact.crown.description',
                  'Highest-risk crown-jewel assets ({total} in total).',
                  {
                    total: crownData?.total ?? 0,
                  }
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {crownLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-10 w-full" />
                  ))}
                </div>
              ) : topCrownJewels.length === 0 ? (
                <EmptyState
                  icon={Crown}
                  title={t('prioritization.businessImpact.crown.emptyTitle', 'No crown jewels yet')}
                  description={t(
                    'prioritization.businessImpact.crown.emptyDescription',
                    'Mark assets as crown jewels from the Crown jewels page.'
                  )}
                  card={false}
                />
              ) : (
                <div className="divide-y">
                  {topCrownJewels.map((asset) => (
                    <div
                      key={asset.id}
                      className="flex items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0"
                    >
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium">{asset.name}</p>
                        <p className="flex gap-3 text-xs text-muted-foreground">
                          <span className="capitalize">{asset.type}</span>
                          <span>
                            {t('prioritization.businessImpact.crown.findings', '{count} findings', {
                              count: asset.finding_count ?? 0,
                            })}
                          </span>
                        </p>
                      </div>
                      <RiskScoreBadge score={asset.risk_score ?? 0} size="sm" labelled />
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <section className="space-y-3">
          <div>
            <h2 className="text-base font-semibold">
              {t('prioritization.businessImpact.units.title', 'Business units')}
            </h2>
            <p className="text-sm text-muted-foreground">
              {t(
                'prioritization.businessImpact.units.description',
                'Risk by business area ({total} units), riskiest first.',
                {
                  total: buData?.total ?? 0,
                }
              )}
            </p>
          </div>
          {buLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : sortedUnits.length === 0 ? (
            <EmptyState
              icon={Building2}
              title={t('prioritization.businessImpact.units.emptyTitle', 'No business units yet')}
              description={t(
                'prioritization.businessImpact.units.emptyDescription',
                'Create business units from the Scoping section.'
              )}
            />
          ) : (
            <DataTable
              columns={buColumns}
              data={sortedUnits}
              searchPlaceholder={t(
                'prioritization.businessImpact.units.search',
                'Search business units…'
              )}
              emptyMessage={t(
                'prioritization.businessImpact.units.noMatch',
                'No business units match'
              )}
              emptyDescription={t(
                'prioritization.businessImpact.units.noMatchHint',
                'Try a different search.'
              )}
            />
          )}
        </section>
      </PageStack>
    </Main>
  )
}
