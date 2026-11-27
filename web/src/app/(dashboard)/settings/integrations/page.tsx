'use client'

import { IntegrationHealth } from '@/features/integrations/components/integration-health'
import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  LinkCard,
  PageHeader,
  RelativeTime,
  StackedCell,
  PageStack,
} from '@/features/shared'
import {
  IntegrationList,
  integrationStatusGroup,
} from '@/features/integrations/components/integration-list'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Puzzle } from 'lucide-react'
import { INTEGRATION_CATEGORIES as integrationCategories } from '@/features/integrations/config/integration-categories'
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

function categoryLabel(t: TFn, i: Integration): string {
  if (isSiemIntegration(i)) return t('integrationsHub.category.siem', 'SIEM')
  const label = CATEGORY_LABELS[i.category]
  return label ? t(label[0], label[1]) : i.category
}

// The name opens the page that manages the integration (no per-row "Manage"
// button); the status is the shared IntegrationHealth.
function buildColumns(t: TFn): ColumnDef<Integration>[] {
  return [
    {
      accessorKey: 'name',
      header: t('integrationsHub.columns.name', 'Name'),
      meta: { kind: 'name' },
      cell: ({ row }) => {
        const i = row.original
        const problem = i.sync_error || i.status_message
        return (
          <StackedCell
            primary={
              <Link href={integrationManageHref(i)} className="font-medium hover:underline">
                {i.name}
              </Link>
            }
            secondary={
              problem ? (
                <span className="block truncate text-destructive" title={problem}>
                  {problem}
                </span>
              ) : (
                i.description
              )
            }
            truncate
          />
        )
      },
    },
    {
      id: 'category',
      header: t('integrationsHub.columns.category', 'Category'),
      meta: { kind: 'text' },
      accessorFn: (i) => categoryLabel(t, i),
      cell: ({ getValue }) => <Badge variant="outline">{getValue<string>()}</Badge>,
    },
    {
      accessorKey: 'status',
      header: t('integrationsHub.columns.status', 'Status'),
      meta: { kind: 'status' },
      cell: ({ row }) => {
        return <IntegrationHealth status={row.original.status} />
      },
    },
    {
      id: 'last_sync',
      header: t('integrationsHub.columns.lastSync', 'Last sync'),
      meta: { kind: 'datetime-recent' },
      accessorFn: (i) => i.last_sync_at ?? '',
      cell: ({ row }) => <RelativeTime date={row.original.last_sync_at} />,
    },
  ]
}

export default function IntegrationsPage() {
  const { t } = useTranslation()
  const router = useRouter()
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
  const hasRows = integrations.length > 0

  // Destinations: the pages that own each connect flow. While nothing is
  // connected they are the page's first step; once there is a list, the list
  // comes first and these follow it.
  const categories = (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('integrationsHub.title', 'Integrations')}
          description={t(
            'integrationsHub.description',
            'Connect third-party tools and services to your security workflows.'
          )}
        />

        {!hasRows && !isLoading && !error && categories}

        <IntegrationList
          rows={integrations}
          isLoading={isLoading}
          error={error}
          onRetry={() => void mutate()}
          errorTitle={t('integrationsHub.errorTitle', 'integrations')}
          groupOf={(i) => integrationStatusGroup(i.status)}
          empty={{
            icon: Puzzle,
            title: t('integrationsHub.empty.title', 'No integrations configured yet'),
            description: t(
              'integrationsHub.empty.description',
              'Pick a category above to connect your first tool.'
            ),
          }}
        >
          {(visible) => (
            <DataTable
              columns={columns}
              data={visible}
              getRowId={(i) => i.id}
              searchPlaceholder={t('integrationsHub.searchPlaceholder', 'Search integrations…')}
              showSelectionCount={false}
              mobileRow={(i) => (
                <PersonPhoneCard
                  title={i.name}
                  address={categoryLabel(t, i)}
                  facts={<IntegrationHealth status={i.status} />}
                  onOpen={() => router.push(integrationManageHref(i))}
                />
              )}
            />
          )}
        </IntegrationList>

        {hasRows && (
          <section className="space-y-3" aria-labelledby="integrations-add">
            <h2 id="integrations-add" className="text-section">
              {t('integrationsHub.addHeading', 'Connect another tool')}
            </h2>
            {categories}
          </section>
        )}
      </PageStack>
    </Main>
  )
}
