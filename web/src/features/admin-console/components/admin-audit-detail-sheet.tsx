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
import { adminFetcher } from '../api/admin-client'
import { humanizeAction } from './admin-activity-table'
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

  return (
    <DetailSheet
      open={entryId !== null}
      onOpenChange={(open) => !open && onClose()}
      width="lg"
      header={
        <DetailHeader
          title={data ? humanizeAction(data.action) : t('admin.activity.entry', 'Audit entry')}
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
              <RelativeTime date={data.created_at} />
            </DetailField>
            <DetailField label={t('admin.activity.status', 'Response')}>
              <span className="tabular-nums">{data.response_status ?? '-'}</span>
            </DetailField>
            <DetailField label={t('admin.activity.resource', 'Resource')}>
              {data.resource_type ? (
                <span>
                  {data.resource_type}
                  {data.resource_name ? `: ${data.resource_name}` : ''}
                </span>
              ) : (
                '-'
              )}
            </DetailField>
            <DetailField label={t('admin.activity.resourceId', 'Resource ID')}>
              <code className="text-xs break-all">{data.resource_id ?? '-'}</code>
            </DetailField>
            <DetailField label={t('admin.activity.ip', 'IP address')}>
              <span className="tabular-nums">{data.ip_address || '-'}</span>
            </DetailField>
            <DetailField label={t('admin.activity.request', 'Request')}>
              <code className="text-xs break-all">
                {data.request_method} {data.request_path}
              </code>
            </DetailField>
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
