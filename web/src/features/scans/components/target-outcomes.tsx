'use client'

import { useMemo, useState } from 'react'
import { AlertTriangle, ChevronRight, Info } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { ToneChip } from '@/components/ui/tone-chip'
import { useTranslation } from '@/context/i18n-provider'
import { DetailStat, DetailStatGrid } from '@/features/shared/components/detail-sheet'
import { ListSearch } from '@/features/shared/components/list-search'
import { cn } from '@/lib/utils'

import { ConfirmOwnershipAction } from './confirm-ownership-action'

import {
  needsAttention,
  skippedTotal,
  skipReasonKey,
  type SkipGroup,
} from '@/features/scans/lib/skip-groups'

/** Lists longer than this get a search box. */
const SEARCH_FROM = 8

interface TargetOutcomesProps {
  /** Targets the scan dispatches (or would). */
  willScan: number
  groups: SkipGroup[]
  /** `run`: what a run did ("Scanned"); `preview`: what Start would do. */
  variant?: 'preview' | 'run'
  /** Shown inside a reason's group instead of the plain name list. */
  detail?: Partial<Record<string, React.ReactNode>>
  /**
   * Typed targets the user may take out of the scan; with `onRemove`, a
   * group listing some of them offers to remove them.
   */
  removable?: (target: string) => boolean
  onRemove?: (targets: string[]) => void
}

/**
 * What a scan covers: how many targets it scans, and every skipped target
 * grouped by reason with the fix. Skipping is an outcome, not a failure: an
 * expected reason (a name with no DNS answer) is neutral, one that needs a
 * fix is amber, and nothing here is red. Shared by the New / Edit scan
 * review and the run's Dispatch card.
 */
export function TargetOutcomes({
  willScan,
  groups,
  variant = 'preview',
  detail,
  removable,
  onRemove,
}: TargetOutcomesProps) {
  const { t } = useTranslation()
  const skipped = skippedTotal(groups)
  const attention = needsAttention(groups)

  return (
    <div className="space-y-3" data-testid="target-outcomes">
      <DetailStatGrid className="sm:max-w-sm">
        <DetailStat
          label={
            variant === 'run' ? t('scans.targetOutcome.scanned') : t('scans.targetOutcome.willScan')
          }
          value={<span data-testid="outcome-will-scan">{willScan.toLocaleString()}</span>}
        />
        <DetailStat
          label={t('scans.targetOutcome.skipped')}
          tone={attention ? 'warning' : 'default'}
          value={
            <span
              className="inline-flex items-center gap-1.5"
              data-testid="outcome-skipped"
              data-attention={attention || undefined}
            >
              {skipped.toLocaleString()}
              {attention && <AlertTriangle className="h-4 w-4" aria-hidden />}
            </span>
          }
        />
      </DetailStatGrid>

      {groups.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {variant === 'run'
            ? t('scans.targetOutcome.noneSkippedRun')
            : t('scans.targetOutcome.noneSkipped')}
        </p>
      ) : (
        <ul
          className="divide-y rounded-md border"
          aria-label={t('scans.targetOutcome.groupsLabel')}
        >
          {groups.map((g) => (
            <SkipGroupRow
              key={g.reason}
              group={g}
              detail={detail?.[g.reason]}
              removable={removable}
              onRemove={onRemove}
            />
          ))}
        </ul>
      )}
    </div>
  )
}

function SkipGroupRow({
  group,
  detail,
  removable,
  onRemove,
}: {
  group: SkipGroup
  detail?: React.ReactNode
  removable?: (target: string) => boolean
  onRemove?: (targets: string[]) => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const reason = skipReasonKey(group.reason)
  const warning = group.tone === 'warning'
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return q ? group.targets.filter((n) => n.toLowerCase().includes(q)) : group.targets
  }, [group.targets, query])
  const more = group.count - group.targets.length
  const typed = onRemove && removable ? group.targets.filter(removable) : []
  // Names a person can confirm as the organization's in one step.
  const confirmable =
    group.reason === 'ownership_unconfirmed' || group.reason === 'wildcard_only'
      ? group.targets
      : []

  return (
    <li data-reason={group.reason} data-tone={group.tone}>
      <Collapsible open={open} onOpenChange={setOpen}>
        <CollapsibleTrigger asChild>
          <button
            type="button"
            className="flex w-full min-w-0 items-center gap-2 px-3 py-2 text-start hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <ChevronRight
              className={cn('h-4 w-4 shrink-0 transition-transform', open && 'rotate-90')}
              aria-hidden
            />
            <ToneChip
              tone={warning ? 'caution' : 'neutral'}
              icon={warning ? AlertTriangle : Info}
              label={
                warning ? t('scans.targetOutcome.toneWarning') : t('scans.targetOutcome.toneInfo')
              }
            />
            <span className="min-w-0 flex-1 text-sm">
              {t(`scans.targetOutcome.reason.${reason}`)}
            </span>
            <span className="shrink-0 text-sm font-semibold tabular-nums">
              {group.count.toLocaleString()}
            </span>
          </button>
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-2 px-3 pb-3 ps-9">
          <p className="text-xs text-muted-foreground">{t(`scans.targetOutcome.fix.${reason}`)}</p>
          {detail ??
            (group.targets.length === 0 ? (
              <p className="text-xs text-muted-foreground">{t('scans.targetOutcome.countOnly')}</p>
            ) : (
              <>
                {group.targets.length > SEARCH_FROM && (
                  <ListSearch
                    value={query}
                    onChange={setQuery}
                    placeholder={t('scans.targetOutcome.search')}
                    label={t('scans.targetOutcome.searchLabel')}
                    className="sm:max-w-64"
                  />
                )}
                {shown.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    {t('scans.targetOutcome.noMatch')}
                  </p>
                ) : (
                  <ul className="max-h-60 space-y-0.5 overflow-y-auto" data-testid="skip-names">
                    {shown.map((n) => (
                      <li key={n} className="break-all font-mono text-xs">
                        {n}
                      </li>
                    ))}
                  </ul>
                )}
                {more > 0 && (
                  <p className="text-xs text-muted-foreground">
                    {t('scans.targetOutcome.more', undefined, { count: more })}
                  </p>
                )}
              </>
            ))}
          {confirmable.length > 0 && <ConfirmOwnershipAction names={confirmable} />}
          {typed.length > 0 && onRemove && (
            <Button type="button" variant="outline" size="sm" onClick={() => onRemove(typed)}>
              {t('scans.targetOutcome.removeTyped', undefined, { count: typed.length })}
            </Button>
          )}
        </CollapsibleContent>
      </Collapsible>
    </li>
  )
}
