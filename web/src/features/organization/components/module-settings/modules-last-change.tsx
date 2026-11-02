'use client'

import Link from 'next/link'
import { useTranslation } from '@/context/i18n-provider'
import { useAuditLogs } from '@/features/organization/api/use-audit-logs'
import { formatLocalized } from '@/lib/format-date'

/** The audit search that lists module changes (their messages start "Modules updated"). */
export const MODULES_AUDIT_HREF = '/settings/audit-log?q=modules'

const LAST_CHANGE_FILTERS = {
  action: ['tenant.modules_updated'],
  page: 1,
  per_page: 1,
  sort_by: 'logged_at',
  sort_order: 'desc' as const,
}

/**
 * Who changed the modules last, and when, with a link to the audit log.
 * Rendered only for readers with audit:read (the caller checks), so the
 * request is never made for someone the API would refuse.
 */
export function ModulesLastChange() {
  const { t, locale } = useTranslation()
  const { logs, isLoading } = useAuditLogs(LAST_CHANGE_FILTERS)
  const last = logs[0]
  if (isLoading) return null
  return (
    <p className="text-sm text-muted-foreground" data-testid="modules-last-change">
      {last
        ? t('settings.modules.lastChange', 'Last change by {actor}, {date}.', {
            actor: last.actor_email,
            date: formatLocalized(last.timestamp, locale, { time: true }),
          })
        : t('settings.modules.noChanges', 'No module changes recorded yet.')}{' '}
      <Link
        href={MODULES_AUDIT_HREF}
        className="font-medium text-foreground underline-offset-4 hover:underline"
      >
        {t('settings.modules.viewAudit', 'View audit log')}
      </Link>
    </p>
  )
}
