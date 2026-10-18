'use client'

import { useMemo } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  EmptyState,
  ErrorState,
  LinkCard,
  MetricStrip,
  PageHeader,
  RelativeTime,
  StackedCell,
  type MetricStripItem,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Puzzle, CheckCircle, XCircle, RefreshCw, AlertTriangle, ArrowRight } from 'lucide-react'
import { INTEGRATION_CATEGORIES as integrationCategories } from '@/features/integrations/config/integration-categories'
import { Can, Permission } from '@/lib/permissions'
import { useSCMConnections } from '@/features/repositories/hooks/use-repositories'
import type { SCMConnection } from '@/features/repositories/types/repository.types'
import { useIntegrationsApi } from '@/features/integrations/api'
import {
  integrationManageHref,
  isSiemIntegration,
} from '@/features/integrations/lib/integration-routing'
import type {
  Integration,
  IntegrationCategory,
} from '@/features/integrations/types/integration.types'

type TFn = ReturnType<typeof useTranslation>['t']

// Per-category label. The page that manages an integration comes from
// integrationManageHref (SIEM destinations are notification-category rows
// managed on the SIEM page).
const CATEGORY_LABELS: Record<IntegrationCategory, [string, string]> = {
  scm: ['integrationsHub.category.scm', 'Source control'],
  security: ['integrationsHub.category.security', 'Vulnerability scanners'],
  ticketing: ['integrationsHub.category.ticketing', 'Ticketing'],
  cloud: ['integrationsHub.category.cloud', 'Cloud'],
  notification: ['integrationsHub.category.notification', 'Notification channels'],
}

// Status badge for every IntegrationStatus the API can return. Only a problem
// (error / expired) is coloured; everything else stays neutral.
const statusConfig: Record<
  string,
  {
    variant: 'default' | 'secondary' | 'destructive' | 'outline'
    icon: typeof CheckCircle
    key: string
    fallback: string
  }
> = {
  connected: { variant: 'default', icon: CheckCircle, key: 'connected', fallback: 'Connected' },
  disconnected: {
    variant: 'secondary',
    icon: XCircle,
    key: 'disconnected',
    fallback: 'Disconnected',
  },
  error: { variant: 'destructive', icon: XCircle, key: 'error', fallback: 'Error' },
  pending: { variant: 'outline', icon: RefreshCw, key: 'pending', fallback: 'Pending' },
  expired: { variant: 'destructive', icon: AlertTriangle, key: 'expired', fallback: 'Expired' },
  disabled: { variant: 'secondary', icon: XCircle, key: 'disabled', fallback: 'Disabled' },
}

function buildColumns(t: TFn): ColumnDef<Integration>[] {
  return [
    {
      accessorKey: 'name',
      header: t('integrationsHub.columns.name', 'Name'),
      cell: ({ row }) => {
        const i = row.original
        const problem = i.sync_error || i.status_message
        return (
          <StackedCell
            primary={i.name}
            secondary={
              problem ? <span className="text-destructive">{problem}</span> : i.description
            }
            truncate
          />
        )
      },
    },
    {
      id: 'category',
      header: t('integrationsHub.columns.category', 'Category'),
      accessorFn: (i) => {
        if (isSiemIntegration(i)) return t('integrationsHub.category.siem', 'SIEM')
        const label = CATEGORY_LABELS[i.category]
        return label ? t(label[0], label[1]) : i.category
      },
      cell: ({ getValue }) => <Badge variant="outline">{getValue<string>()}</Badge>,
    },
    {
      accessorKey: 'status',
      header: t('integrationsHub.columns.status', 'Status'),
      cell: ({ row }) => {
        const s = statusConfig[row.original.status] ?? statusConfig.disconnected
        return (
          <Badge variant={s.variant} className="gap-1">
            <s.icon className="h-3 w-3" />
            {t(`integrationsHub.status.${s.key}`, s.fallback)}
          </Badge>
        )
      },
    },
    {
      id: 'last_sync',
      header: t('integrationsHub.columns.lastSync', 'Last sync'),
      accessorFn: (i) => i.last_sync_at ?? '',
      cell: ({ row }) => <RelativeTime date={row.original.last_sync_at} />,
    },
    {
      id: 'actions',
      enableSorting: false,
      cell: ({ row }) => (
        <Can permission={Permission.IntegrationsRead} mode="hide">
          <Button variant="ghost" size="sm" asChild>
            <Link href={integrationManageHref(row.original)}>
              {t('integrationsHub.manage', 'Manage')}
              <ArrowRight className="ms-1 h-4 w-4" />
            </Link>
          </Button>
        </Can>
      ),
    },
  ]
}

export default function IntegrationsPage() {
  const { t } = useTranslation()
  const columns = useMemo(() => buildColumns(t), [t])
  const { data: scmConnectionsData } = useSCMConnections()
  const { data: integrationsData, error, isLoading, mutate } = useIntegrationsApi()

  // SCM connections power the per-category badge on the SCM card.
  const scmConnections: SCMConnection[] = Array.isArray(scmConnectionsData)
    ? scmConnectionsData
    : ((scmConnectionsData as unknown as { data?: SCMConnection[] })?.data ?? [])
  const scmConnectedCount = scmConnections.filter((c) => c.status === 'connected').length

  // All configured integrations across every category (real data).
  const integrations: Integration[] = integrationsData?.data ?? []
  const connectedCount = integrations.filter((i) => i.status === 'connected').length
  const needsAttentionCount = integrations.filter(
    (i) => i.status === 'error' || i.status === 'expired'
  ).length
  const pendingCount = integrations.filter(
    (i) => i.status === 'pending' || i.status === 'disconnected'
  ).length

  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('integrationsHub.metrics.total', 'Total integrations'),
      value: integrations.length,
    },
    {
      key: 'connected',
      label: t('integrationsHub.metrics.connected', 'Connected'),
      value: connectedCount,
    },
    {
      key: 'attention',
      label: t('integrationsHub.metrics.attention', 'Needs attention'),
      value: needsAttentionCount,
      tone: 'danger',
    },
    { key: 'pending', label: t('integrationsHub.metrics.pending', 'Pending'), value: pendingCount },
  ]

  return (
    <Main>
      <PageHeader
        title={t('integrationsHub.title', 'Integrations')}
        description={t(
          'integrationsHub.description',
          'Connect third-party tools and services to your security workflows.'
        )}
      />

      {/* Categories — navigation to the pages that own each connect flow */}
      <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {integrationCategories.map((category) => (
          <LinkCard
            key={category.id}
            href={category.href}
            icon={category.icon}
            title={t(`integrationsHub.categories.${category.id}.title`, category.title)}
            description={t(
              `integrationsHub.categories.${category.id}.description`,
              category.description
            )}
            badge={category.badge ? t('integrationsHub.badge.soon', category.badge) : undefined}
            aside={
              category.id === 'scm' && scmConnections.length > 0 ? (
                <Badge variant="secondary" className="tabular-nums">
                  {scmConnectedCount}/{scmConnections.length}
                </Badge>
              ) : undefined
            }
          />
        ))}
      </div>

      <MetricStrip className="mt-5" loading={isLoading} items={metrics} />

      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('integrationsHub.errorTitle', 'integrations')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-9 w-full max-w-sm" />
            <Skeleton className="h-48 w-full" />
          </div>
        ) : integrations.length === 0 ? (
          <EmptyState
            icon={Puzzle}
            title={t('integrationsHub.empty.title', 'No integrations configured yet')}
            description={t(
              'integrationsHub.empty.description',
              'Pick a category above to connect your first tool.'
            )}
          />
        ) : (
          <DataTable
            columns={columns}
            data={integrations}
            getRowId={(i) => i.id}
            searchPlaceholder={t('integrationsHub.searchPlaceholder', 'Search integrations...')}
            showSelectionCount={false}
          />
        )}
      </div>
    </Main>
  )
}
