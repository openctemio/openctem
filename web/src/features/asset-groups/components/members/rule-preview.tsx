'use client'

/**
 * Live preview of a group rule: how many assets it matches now, as the
 * signed-in person (inside their data scope), the first matches, and for a
 * group being edited who would join and leave.
 */

import { useMemo } from 'react'
import useSWR from 'swr'
import { Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useDebounce } from '@/hooks/use-debounce'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { previewGroupRule } from '../../api/use-group-rule-api'
import type { GroupRuleDocument } from '../../types'
import { ImpactNotice } from './impact-notice'

interface RulePreviewProps {
  rule: GroupRuleDocument | null
  /** Set for a group being edited. */
  groupId?: string
  /** A problem with the rule that stops the preview (shown instead). */
  blockedReason?: string
}

export function RulePreview({ rule, groupId, blockedReason }: RulePreviewProps) {
  const { t } = useTranslation()
  const body = useMemo(() => (rule ? JSON.stringify({ rule, groupId }) : null), [rule, groupId])
  const settled = useDebounce(body, 500)
  const key = settled && !blockedReason ? ['group-rule-preview', settled] : null
  const { data, error, isLoading } = useSWR(
    key,
    () => previewGroupRule(rule as GroupRuleDocument, groupId),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      keepPreviousData: true,
      onError: () => undefined,
    }
  )

  if (blockedReason) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="rule-preview-blocked">
        {blockedReason}
      </p>
    )
  }
  if (!rule) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="rule-preview-empty">
        {t('assetGroups.members.preview.empty', 'Add a condition to see which assets match.')}
      </p>
    )
  }
  if (error && !data) {
    return (
      <p className="text-sm text-destructive" role="alert" data-testid="rule-preview-error">
        {getErrorMessage(error, t('assetGroups.members.preview.failed', 'The preview failed'))}
      </p>
    )
  }
  return (
    <div className="space-y-3" data-testid="rule-preview" aria-live="polite">
      <div className="flex flex-wrap items-center gap-2">
        {isLoading || settled !== body ? (
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-hidden />
        ) : null}
        {data ? (
          <span className="text-sm font-medium" data-testid="rule-preview-count">
            {data.over_cap
              ? t('assetGroups.members.preview.overCap', 'More than {cap} assets match', {
                  cap: data.cap.toLocaleString(),
                })
              : t('assetGroups.members.preview.count', '{count} assets match', {
                  count: data.count.toLocaleString(),
                })}
          </span>
        ) : null}
        {data && groupId ? (
          <>
            <Badge variant="outline">
              {t('assetGroups.members.preview.wouldJoin', '{count} would join', {
                count: data.would_join,
              })}
            </Badge>
            <Badge variant="outline">
              {t('assetGroups.members.preview.wouldLeave', '{count} would leave', {
                count: data.would_leave,
              })}
            </Badge>
          </>
        ) : null}
      </div>
      {data?.over_cap ? (
        <p className="text-sm text-destructive" role="alert">
          {t(
            'assetGroups.members.preview.overCapHelp',
            'A group holds at most {cap} assets. Narrow the rule before saving.',
            { cap: data.cap.toLocaleString() }
          )}
        </p>
      ) : null}
      {data && data.sample.length > 0 ? (
        <div>
          <p className="mb-1 text-xs text-muted-foreground">
            {t('assetGroups.members.preview.sample', 'First {count} matches', {
              count: data.sample.length,
            })}
          </p>
          <ul className="grid gap-1 text-sm sm:grid-cols-2">
            {data.sample.map((a) => (
              <li key={a.id} className="truncate rounded border px-2 py-1" title={a.name}>
                {a.name}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <ImpactNotice impact={data?.impact} />
    </div>
  )
}
