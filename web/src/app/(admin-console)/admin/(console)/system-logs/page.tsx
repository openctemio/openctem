'use client'

import { Main } from '@/components/layout'
import { Input } from '@/components/ui/input'
import { ErrorState, PageHeader } from '@/features/shared'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import { useAdminAuditLogs } from '@/features/admin-console/api/use-admin-audit'
import { AdminActivityTable } from '@/features/admin-console/components/admin-activity-table'

export default function SystemLogsPage() {
  // The list lives in the URL (one list convention): page and its filters.
  const list = useListParams({ filters: { action: '', admin_email: '' } })
  const { page, setPage } = list
  const action = list.filters.action
  const adminEmail = list.filters.admin_email
  const dAction = useDebounce(action, 300)
  const dEmail = useDebounce(adminEmail, 300)
  const { data, error, isLoading, mutate } = useAdminAuditLogs({
    page,
    action: dAction,
    adminEmail: dEmail,
  })

  return (
    <Main>
      <PageHeader
        title="System logs"
        description="Every action taken by platform administrators, including sign-ins and refused attempts."
      />
      <div className="mt-5">
        {error ? (
          <ErrorState title="system logs" error={error} onRetry={() => void mutate()} />
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
                  placeholder="Action, e.g. console.login"
                  value={action}
                  onChange={(e) => list.setFilter('action', e.target.value)}
                  className="sm:max-w-xs"
                  aria-label="Filter by action"
                />
                <Input
                  placeholder="Administrator email"
                  value={adminEmail}
                  onChange={(e) => list.setFilter('admin_email', e.target.value)}
                  className="sm:max-w-xs"
                  aria-label="Filter by administrator"
                />
              </div>
            }
          />
        )}
      </div>
    </Main>
  )
}
