'use client'

import { useMemo, useState } from 'react'
import { Download } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ErrorState, PageHeader } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useCsvExport, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import { useAdminAuditLogs, type AuditOutcome } from '@/features/admin-console/api/use-admin-audit'
import { AdminActivityTable } from '@/features/admin-console/components/admin-activity-table'
import { AdminAuditDetailSheet } from '@/features/admin-console/components/admin-audit-detail-sheet'
import { dayBound } from '@/features/admin-console/lib/audit-range'
import type { AdminAuditEntry } from '@/features/admin-console/types'

const ALL = 'all'
const EXPORT_FIELDS: ExportFieldConfig<AdminAuditEntry>[] = [
  { header: 'When', accessor: (e) => e.created_at },
  { header: 'Administrator', accessor: (e) => e.admin_email },
  { header: 'Action', accessor: (e) => e.action },
  { header: 'Resource type', accessor: (e) => e.resource_type ?? '' },
  { header: 'Resource ID', accessor: (e) => e.resource_id ?? '' },
  { header: 'Result', accessor: (e) => (e.success ? 'succeeded' : 'failed') },
  { header: 'HTTP status', accessor: (e) => e.response_status ?? '' },
  { header: 'IP address', accessor: (e) => e.ip_address ?? '' },
]

export default function AdminActivityPage() {
  const { t } = useTranslation()
  // The list lives in the URL (one list convention): page and its filters, so
  // the overview can link straight to "break-glass sign-ins" or "failures".
  const list = useListParams({
    filters: { action: '', admin_email: '', outcome: '', from: '', to: '' },
  })
  const { page, setPage } = list
  const action = list.filters.action
  const adminEmail = list.filters.admin_email
  const outcome: AuditOutcome =
    list.filters.outcome === 'success' || list.filters.outcome === 'failure'
      ? list.filters.outcome
      : ''
  const dAction = useDebounce(action, 300)
  const dEmail = useDebounce(adminEmail, 300)
  const { data, error, isLoading, mutate } = useAdminAuditLogs({
    page,
    action: dAction,
    adminEmail: dEmail,
    outcome,
    from: dayBound(list.filters.from, false),
    to: dayBound(list.filters.to, true),
  })
  const [openId, setOpenId] = useState<string | null>(null)
  const entries = useMemo(() => data?.data ?? [], [data])
  const { handleExport } = useCsvExport(entries, EXPORT_FIELDS, 'admin-activity')

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.activity', 'Admin activity')}
        description={t(
          'admin.activity.description',
          'Every action taken by platform administrators, including sign-ins and refused attempts.'
        )}
      >
        <Button size="sm" variant="outline" onClick={handleExport} disabled={entries.length === 0}>
          <Download className="me-2 size-4" />
          {t('admin.activity.export', 'Export this page (CSV)')}
        </Button>
      </PageHeader>
      <div className="mt-5">
        {error ? (
          <ErrorState title="admin activity" error={error} onRetry={() => void mutate()} />
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
                <Select
                  value={outcome || ALL}
                  onValueChange={(v) => list.setFilter('outcome', v === ALL ? '' : v)}
                >
                  <SelectTrigger
                    className="lg:w-44"
                    aria-label={t('admin.activity.outcomeLabel', 'Filter by result')}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ALL}>
                      {t('admin.activity.outcomeAll', 'All results')}
                    </SelectItem>
                    <SelectItem value="success">
                      {t('admin.activity.outcomeSuccess', 'Succeeded')}
                    </SelectItem>
                    <SelectItem value="failure">
                      {t('admin.activity.outcomeFailure', 'Refused or failed')}
                    </SelectItem>
                  </SelectContent>
                </Select>
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
      </div>
      <AdminAuditDetailSheet entryId={openId} onClose={() => setOpenId(null)} />
    </Main>
  )
}
