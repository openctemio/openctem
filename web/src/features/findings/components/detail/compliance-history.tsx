'use client'

/**
 * The status history of the benchmark control a compliance finding fails:
 * the first result the platform saw and every later change of result or
 * evidence, newest first (GET /findings/{id}/compliance-history). Folded by
 * default: the current result is already in the section's header.
 */

import { useTranslation } from '@/context/i18n-provider'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailDisclosure } from '@/features/shared/components/detail-sheet'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import { formatRelative } from '@/lib/format-date'
import { useFindingComplianceHistory } from '../../api/compliance-checks-api'
import { ComplianceResultChip } from '../compliance-benchmark-sheet'

export function ComplianceHistory({ findingId }: { findingId: string }) {
  const { t, locale } = useTranslation()
  const { data, error, isLoading } = useFindingComplianceHistory(findingId)
  if (error) return null
  if (isLoading && !data) return <Skeleton className="h-6 w-48" />
  const entries = data?.data ?? []
  if (!data?.control || entries.length === 0) return null
  return (
    <DetailDisclosure
      summary={t('findings.complianceView.history', 'Status history ({count})', {
        count: entries.length,
      })}
    >
      <ol className="mt-2 space-y-2" data-testid="compliance-history">
        {entries.map((e, i) => (
          <li key={i} className="space-y-1">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <ComplianceResultChip result={e.result} />
              {e.previous_result && (
                <span className="text-muted-foreground">
                  {t('findings.complianceView.was', 'was {result}', {
                    result: t(
                      `findings.filter.value.compliance_result.${e.previous_result}`,
                      e.previous_result
                    ),
                  })}
                </span>
              )}
              <time className="text-muted-foreground" dateTime={e.observed_at}>
                {formatRelative(e.observed_at, '', locale)}
              </time>
              {e.source === 'backfill' && (
                <span className="text-xs text-muted-foreground">
                  {t('findings.complianceView.fromStored', 'from the stored finding')}
                </span>
              )}
            </div>
            {e.evidence.actual && (
              <UntrustedTextBlock
                text={e.evidence.actual}
                label={t('findings.compliance.actual', 'Actual value')}
                collapseLines={4}
              />
            )}
          </li>
        ))}
      </ol>
    </DetailDisclosure>
  )
}
