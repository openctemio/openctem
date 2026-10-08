'use client'

import { Main } from '@/components/layout'
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
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import { useAdminAuditLogs, type AuditOutcome } from '@/features/admin-console/api/use-admin-audit'
import { AdminActivityTable } from '@/features/admin-console/components/admin-activity-table'

const ALL = 'all'

export default function AdminActivityPage() {
  const { t } = useTranslation()
  // The list lives in the URL (one list convention): page and its filters, so
  // the overview can link straight to "break-glass sign-ins" or "failures".
  const list = useListParams({ filters: { action: '', admin_email: '', outcome: '' } })
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
  })

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.activity', 'Admin activity')}
        description={t(
          'admin.activity.description',
          'Every action taken by platform administrators, including sign-ins and refused attempts.'
        )}
      />
      <div className="mt-5">
        {error ? (
          <ErrorState title="admin activity" error={error} onRetry={() => void mutate()} />
        ) : (
          <AdminActivityTable
            entries={data?.data ?? []}
            isLoading={isLoading}
            paging={{
              page,
              pageCount: data?.total_pages ?? 1,
              rowCount: data?.total ?? 0,
              onPageChange: setPage,
            }}
            toolbarStart={
              <div className="flex w-full flex-col gap-2 sm:flex-row">
                <Input
                  placeholder={t('admin.activity.actionFilter', 'Action, e.g. console.login')}
                  value={action}
                  onChange={(e) => list.setFilter('action', e.target.value)}
                  className="sm:max-w-xs"
                  aria-label={t('admin.activity.actionFilterLabel', 'Filter by action')}
                />
                <Input
                  placeholder={t('admin.activity.adminFilter', 'Administrator email')}
                  value={adminEmail}
                  onChange={(e) => list.setFilter('admin_email', e.target.value)}
                  className="sm:max-w-xs"
                  aria-label={t('admin.activity.adminFilterLabel', 'Filter by administrator')}
                />
                <Select
                  value={outcome || ALL}
                  onValueChange={(v) => list.setFilter('outcome', v === ALL ? '' : v)}
                >
                  <SelectTrigger
                    className="sm:w-44"
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
              </div>
            }
          />
        )}
      </div>
    </Main>
  )
}
