'use client'

import { ChevronLeft, ChevronRight, History } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useAccountActivity } from '@/features/account'
import { formatAction } from '@/features/organization/types/audit.types'
import { EmptyState, ErrorState } from '@/features/shared'
import { useDisplayUser } from '@/hooks/use-display-user'
import { useListParams } from '@/hooks/use-list-params'
import { formatDateSafe, formatRelative } from '@/lib/format-date'

const PER_PAGE = 10

/**
 * Your activity: the signed-in person's own recent actions in this
 * organization (GET /audit-logs/users/{id}, paged on the server, the page in
 * the URL). One flat list in the settings column (the /settings/me layout):
 * each row is the translated action, when, and from where; a failed or
 * refused action says so. The server's free-text message is English only and
 * mostly repeats the action, so the list shows the translated action alone;
 * the full record stays in the organization's audit log.
 */
export default function ActivityPage() {
  const { t } = useTranslation()
  const user = useDisplayUser()
  const { page, setPage } = useListParams({ defaultPageSize: PER_PAGE })
  const { activities, total, totalPages, isLoading, error, mutate } = useAccountActivity(
    user?.id,
    page,
    PER_PAGE
  )

  const resultText: Record<string, string> = {
    failure: t('auditLog.result.failure', 'Failure'),
    denied: t('auditLog.result.denied', 'Denied'),
  }

  return (
    <>
      {isLoading ? (
        <div className="flex flex-col gap-2" aria-busy="true">
          {[...Array(5)].map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : error && activities.length === 0 ? (
        <ErrorState
          title={t('account.activity.loadFailed', 'your activity')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : activities.length === 0 ? (
        <EmptyState icon={History} title={t('account.activity.empty', 'No activity found')} />
      ) : (
        <section aria-label={t('settings.item.activity', 'Activity')} className="min-w-0">
          <ul className="divide-y divide-border-subtle border-y border-border-subtle">
            {activities.map((activity) => {
              const failed = resultText[activity.result]
              return (
                <li key={activity.id} className="min-w-0 py-3">
                  <p className="text-body font-medium text-pretty">
                    {formatAction(activity.action, t)}
                  </p>
                  <p className="mt-0.5 flex flex-wrap gap-x-3 text-cap text-muted-foreground">
                    <span title={formatDateSafe(activity.timestamp, 'PPpp')}>
                      {formatRelative(activity.timestamp)}
                    </span>
                    {activity.actor_ip && <span>{activity.actor_ip}</span>}
                    {failed && <span className="font-medium text-destructive">{failed}</span>}
                  </p>
                </li>
              )
            })}
          </ul>
          {totalPages > 1 && (
            <div className="mt-3 flex items-center justify-between gap-3">
              <p className="min-w-0 text-cap text-muted-foreground">
                {t('account.activity.showing', 'Showing {from} to {to} of {total} activities', {
                  from: (page - 1) * PER_PAGE + 1,
                  to: Math.min(page * PER_PAGE, total),
                  total,
                })}
              </p>
              <div className="flex shrink-0 items-center gap-2">
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => setPage(page - 1)}
                  disabled={page === 1}
                  aria-label={t('account.activity.prev', 'Previous page')}
                >
                  <ChevronLeft aria-hidden />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => setPage(page + 1)}
                  disabled={page === totalPages}
                  aria-label={t('account.activity.next', 'Next page')}
                >
                  <ChevronRight aria-hidden />
                </Button>
              </div>
            </div>
          )}
        </section>
      )}

      <p className="text-cap text-muted-foreground text-pretty">
        {t(
          'account.activity.tip',
          'Something you do not recognise? Change your password and sign out your other sessions.'
        )}{' '}
        <Link href="/account/security" className="link-inline">
          {t('account.activity.tipLink', 'Open account security')}
        </Link>
      </p>
    </>
  )
}
