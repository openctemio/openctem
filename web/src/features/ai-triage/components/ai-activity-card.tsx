'use client'

import Link from '@/components/link'
import { History } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useAuditLogs } from '@/features/organization/api/use-audit-logs'
import { EmptyState, ErrorState, ListItem, RelativeTime } from '@/features/shared'
import { canonicalAuditAction } from '@/lib/api/audit-types'
import { humanizeIdentifier } from '@/lib/humanize-identifier'

/** The audit actions this card lists: AI settings changes and AI triage outcomes. */
export const AI_ACTIVITY_ACTIONS = [
  'ai_settings.updated',
  'ai_settings.tested',
  'ai_settings.auto_triage_updated',
  'ai_settings.masking_updated',
  'ai_triage.completed',
  'ai_triage.failed',
  'ai_triage.needs_review',
  'ai_triage.budget_exhausted',
  'ai_knowledge.source_approved',
  'ai_knowledge.source_disabled',
]

/**
 * The latest AI events from the audit log (holders of audit:read only; the
 * page shows this tab only to them), with a link to the full log. Read only
 * when the tab is open.
 */
export function AIActivityCard() {
  const { t } = useTranslation()
  const { logs, error, isLoading, mutate } = useAuditLogs({
    action: AI_ACTIVITY_ACTIONS,
    per_page: 8,
    page: 1,
    sort_order: 'desc',
  })
  const rows = logs

  return (
    <Card id="ai-activity">
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <History className="h-4 w-4" aria-hidden />
            {t('settings.ai.activity.title', 'Recent AI activity')}
          </CardTitle>
          <CardDescription>
            {t(
              'settings.ai.activity.description',
              'Changes to these settings and the outcome of AI analyses, from the audit log.'
            )}
          </CardDescription>
        </div>
        <Button asChild variant="outline" size="sm" className="shrink-0">
          <Link href="/settings/audit-log?q=ai_">
            {t('settings.ai.activity.open', 'Audit log')}
          </Link>
        </Button>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : error ? (
          <ErrorState
            title={t('settings.ai.activity.what', 'AI activity')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={History}
            title={t('settings.ai.activity.emptyTitle', 'No AI activity yet')}
            description={t(
              'settings.ai.activity.empty',
              'When AI triage runs or these settings change, it is listed here.'
            )}
          />
        ) : (
          <ul className="divide-y rounded-md border">
            {rows.map((row) => (
              <ListItem
                key={row.id}
                title={row.message || humanizeIdentifier(canonicalAuditAction(row.action))}
                meta={[
                  row.actor_email || t('settings.ai.activity.system', 'System'),
                  <RelativeTime key="t" date={row.timestamp} />,
                ]}
              />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
