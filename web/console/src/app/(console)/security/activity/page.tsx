'use client'

import { useMemo, useState } from 'react'
import { Download } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ErrorState, FilterSelect, PageHeader, PageStack } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useCsvExport, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useListParams } from '@/hooks/use-list-params'
import {
  useAdminAuditLogs,
  type AuditOutcome,
} from '@console/features/admin-console/api/use-admin-audit'
import { AdminActivityTable } from '@console/features/admin-console/components/admin-activity-table'
import {
  AuditKindLens,
  auditKind,
} from '@console/features/admin-console/components/audit-kind-lens'
import { AdminAuditChainStatus } from '@console/features/admin-console/components/admin-audit-chain-status'
import { AdminAuditDetailSheet } from '@console/features/admin-console/components/admin-audit-detail-sheet'
import { dayBound } from '@console/features/admin-console/lib/audit-range'
import type { AdminAuditEntry } from '@console/features/admin-console/types'

const exportFields = (
  t: ReturnType<typeof useTranslation>['t']
): ExportFieldConfig<AdminAuditEntry>[] => [
  { header: t('admin.securityActivityPage.when', 'When'), accessor: (e) => e.created_at },
  {
    header: t('admin.securityActivityPage.administrator', 'Administrator'),
    accessor: (e) => e.admin_email,
  },
  { header: t('admin.securityActivityPage.action', 'Action'), accessor: (e) => e.action },
  {
    header: t('admin.securityActivityPage.resourceType', 'Resource type'),
    accessor: (e) => e.resource_type ?? '',
  },
  {
    header: t('admin.securityActivityPage.resourceId', 'Resource ID'),
    accessor: (e) => e.resource_id ?? '',
  },
  {
    header: t('admin.securityActivityPage.result', 'Result'),
    accessor: (e) => (e.success ? 'succeeded' : 'failed'),
  },
  {
    header: t('admin.securityActivityPage.httpStatus', 'HTTP status'),
    accessor: (e) => e.response_status ?? '',
  },
  {
    header: t('admin.securityActivityPage.ipAddress', 'IP address'),
    accessor: (e) => e.ip_address ?? '',
  },
]

export default function AdminActivityPage() {
  const { t } = useTranslation()
  // The list lives in the URL (one list convention): page and its filters, so
  // the overview can link straight to "break-glass sign-ins" or "failures".
  const list = useListParams({
    filters: { kind: '', action: '', admin_email: '', outcome: '', from: '', to: '' },
  })
  // Changes by default: page views and write-ahead rows stay in the chain,
  // one click away under "All events".
  const kind = auditKind(list.filters.kind)
  const { page, setPage } = list
  const action = list.filters.action
  const adminEmail = list.filters.admin_email
  const outcome: AuditOutcome =
    list.filters.outcome === 'success' || list.filters.outcome === 'failure'
      ? list.filters.outcome
      : ''
  const dAction = useSearchQuery(action).term
  const dEmail = useSearchQuery(adminEmail).term
  const { data, error, isLoading, mutate } = useAdminAuditLogs({
    page,
    action: dAction,
    adminEmail: dEmail,
    outcome,
    kind,
    from: dayBound(list.filters.from, false),
    to: dayBound(list.filters.to, true),
  })
  const [openId, setOpenId] = useState<string | null>(null)
  const entries = useMemo(() => data?.data ?? [], [data])
  const { handleExport } = useCsvExport(entries, exportFields(t), 'admin-activity')

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.activity', 'Admin activity')}
          description={t(
            'admin.activity.description',
            'Every action taken by platform administrators, including sign-ins and refused attempts.'
          )}
        >
          <Button
            size="sm"
            variant="outline"
            onClick={handleExport}
            disabled={entries.length === 0}
          >
            <Download className="me-2 size-4" />
            {t('admin.activity.export', 'Export this page (CSV)')}
          </Button>
        </PageHeader>
        <AdminAuditChainStatus />
        {error ? (
          <ErrorState
            title={t('admin.securityActivityPage.adminActivity', 'admin activity')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : (
          <AdminActivityTable
            entries={entries}
            isLoading={isLoading}
            onRowClick={(e) => setOpenId(e.id)}
            paging={{
              page,
              pageCount: data?.total_pages ?? 1,
              rowCount: data?.total ?? 0,
              onPageChange: setPage,
            }}
            toolbarStart={
              <div className="grid w-full gap-2 sm:grid-cols-2 lg:flex lg:flex-wrap">
                <AuditKindLens
                  value={kind}
                  onChange={(v) => list.setFilter('kind', v === 'all' ? 'all' : '')}
                />
                <Input
                  placeholder={t('admin.activity.actionFilter', 'Action, e.g. console.login')}
                  value={action}
                  onChange={(e) => list.setFilter('action', e.target.value)}
                  className="lg:max-w-56"
                  aria-label={t('admin.activity.actionFilterLabel', 'Filter by action')}
                />
                <Input
                  placeholder={t('admin.activity.adminFilter', 'Administrator email')}
                  value={adminEmail}
                  onChange={(e) => list.setFilter('admin_email', e.target.value)}
                  className="lg:max-w-56"
                  aria-label={t('admin.activity.adminFilterLabel', 'Filter by administrator')}
                />
                <FilterSelect
                  label={t('admin.activity.outcomeLabel', 'Filter by result')}
                  value={outcome}
                  onChange={(v) => list.setFilter('outcome', v)}
                  allLabel={t('admin.activity.outcomeAll', 'All results')}
                  options={[
                    { value: 'success', label: t('admin.activity.outcomeSuccess', 'Succeeded') },
                    {
                      value: 'failure',
                      label: t('admin.activity.outcomeFailure', 'Refused or failed'),
                    },
                  ]}
                />
                <Input
                  type="date"
                  value={list.filters.from}
                  onChange={(e) => list.setFilter('from', e.target.value)}
                  className="lg:w-40"
                  aria-label={t('admin.activity.from', 'From date')}
                />
                <Input
                  type="date"
                  value={list.filters.to}
                  onChange={(e) => list.setFilter('to', e.target.value)}
                  className="lg:w-40"
                  aria-label={t('admin.activity.to', 'To date')}
                />
              </div>
            }
          />
        )}
        <AdminAuditDetailSheet entryId={openId} onClose={() => setOpenId(null)} />
      </PageStack>
    </Main>
  )
}
