'use client'

import useSWR from 'swr'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSheet,
  RelativeTime,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { adminFetcher } from '@console/lib/admin-api/client'
import { toDisplayText } from '@/lib/untrusted-text'
import { auditActionLabel } from '../lib/audit-action-label'
import { formatUtcTime } from '../lib/format-utc'
import type { AdminAuditEntry } from '../types'

/** GET /admin/audit-logs/{id}: the row plus the (redacted) request. */
interface AdminAuditDetail extends AdminAuditEntry {
  request_body?: Record<string, unknown>
  user_agent?: string
}

/**
 * One administrator audit row in full: who, what, on which resource, the
 * outcome, and the request as stored. Secrets (passwords, tokens,
 * authenticator codes) are redacted by the API before the row is written.
 */
export function AdminAuditDetailSheet({
  entryId,
  onClose,
}: {
  entryId: string | null
  onClose: () => void
}) {
  const { t } = useTranslation()
  const { data, isLoading } = useSWR<AdminAuditDetail>(
    entryId ? `/audit-logs/${encodeURIComponent(entryId)}` : null,
    adminFetcher
  )

  const utc = data ? formatUtcTime(data.created_at) : ''
  const request = data ? [data.request_method, data.request_path].filter(Boolean).join(' ') : ''
  // The console sends a reason with a privileged change; the API keeps it in
  // the stored request. It is text from the request body: shown as plain text.
  const rawReason = data?.request_body?.reason
  const reason = typeof rawReason === 'string' ? toDisplayText(rawReason).trim() : ''

  return (
    <DetailSheet
      open={entryId !== null}
      onOpenChange={(open) => !open && onClose()}
      width="lg"
      header={
        <DetailHeader
          title={data ? auditActionLabel(t, data.action) : t('admin.activity.entry', 'Audit entry')}
          badges={
            data &&
            (data.success ? (
              <Badge variant="secondary">{t('admin.activity.outcomeSuccess', 'Succeeded')}</Badge>
            ) : (
              <Badge variant="destructive">{t('admin.activity.failed', 'Failed')}</Badge>
            ))
          }
          meta={data ? [data.action, data.admin_email] : []}
          onClose={onClose}
        />
      }
    >
      {isLoading || !data ? (
        <Skeleton className="h-48 w-full" />
      ) : (
        <div className="space-y-5">
          <DetailFieldGrid>
            <DetailField label={t('admin.activity.when', 'When')}>
              {utc ? (
                <>
                  <time dateTime={data.created_at} className="tabular-nums">
                    {utc}
                  </time>
                  <RelativeTime
                    date={data.created_at}
                    className="block text-cap text-muted-foreground"
                  />
                </>
              ) : (
                <RelativeTime date={data.created_at} />
              )}
            </DetailField>
            {data.response_status != null && (
              <DetailField label={t('admin.activity.status', 'Response')}>
                <span className="tabular-nums">{data.response_status}</span>
              </DetailField>
            )}
            {data.resource_type && (
              <DetailField label={t('admin.activity.resource', 'Resource')}>
                <span>
                  {data.resource_type}
                  {data.resource_name ? `: ${toDisplayText(data.resource_name)}` : ''}
                </span>
              </DetailField>
            )}
            {data.resource_id && (
              <DetailField label={t('admin.activity.resourceId', 'Resource ID')}>
                <code className="text-code break-all">{data.resource_id}</code>
              </DetailField>
            )}
            {data.ip_address && (
              <DetailField label={t('admin.activity.ip', 'IP address')}>
                <span className="tabular-nums">{data.ip_address}</span>
              </DetailField>
            )}
            {request && (
              <DetailField label={t('admin.activity.request', 'Request')}>
                <code className="text-code break-all">{request}</code>
              </DetailField>
            )}
            {reason && (
              <DetailField label={t('admin.activity.reason', 'Reason')} full>
                <span className="text-body break-words whitespace-pre-wrap">{reason}</span>
              </DetailField>
            )}
            {data.user_agent && (
              <DetailField label={t('admin.activity.userAgent', 'Browser')} full>
                <span className="text-xs break-all text-muted-foreground">{data.user_agent}</span>
              </DetailField>
            )}
            {data.error_message && (
              <DetailField label={t('admin.activity.error', 'Error')} full>
                <span className="text-sm text-destructive">{data.error_message}</span>
              </DetailField>
            )}
          </DetailFieldGrid>
          {data.request_body && Object.keys(data.request_body).length > 0 && (
            <section className="space-y-2">
              <h3 className="text-sm font-medium">
                {t('admin.activity.body', 'Request body (secrets redacted)')}
              </h3>
              <pre className="max-h-80 overflow-auto rounded-md bg-muted p-3 text-xs">
                {JSON.stringify(data.request_body, null, 2)}
              </pre>
            </section>
          )}
        </div>
      )}
    </DetailSheet>
  )
}
