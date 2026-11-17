'use client'

import { Checkbox } from '@/components/ui/checkbox'
import { useTranslation } from '@/context/i18n-provider'
import { MetaLine, RelativeTime, type MobileRowSelection } from '@/features/shared'
import type { ScanRun } from '@/lib/api/scan-workflow-types'
import { runTriggeredByLabel } from '@/features/scans/lib/run-display'
import { IntensityBadge } from './intensity-badge'
import { RunScanCell, RunStateLine, RunTasksText, runDurationText } from './scan-run-cells'

/**
 * A scan run on a phone. Fixed slots, one fact per element, never a
 * label/value grid:
 *
 *   Weekly web scan (the whole width, two lines at most)
 *   Partial  Active  Scan run completed partially: 2 of 6 ste...
 *   4/6 tasks, 2 failed   3 findings
 *   Ana Example   2 hours ago   20m
 *
 * The state and its reason are one line: the state chip never wraps or
 * shrinks, the reason is cut to the room left (whole in its hover text and in
 * the run's sheet). Every line has a fixed height whatever the data, so a
 * long message cannot stretch the card. A tap opens the run's sheet.
 */
export function ScanRunMobileCard({
  run,
  selection,
  onOpen,
}: {
  run: ScanRun
  selection: MobileRowSelection
  onOpen: (run: ScanRun) => void
}) {
  const { t } = useTranslation()
  const who = runTriggeredByLabel(run, t) ?? run.trigger_type
  const duration = runDurationText(run, t)
  return (
    <div
      data-slot="run-card"
      data-state={selection.selected ? 'selected' : undefined}
      className="flex cursor-pointer items-start gap-3 px-3 py-3 hover:bg-muted/50 data-[state=selected]:bg-muted"
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a[href], [role="checkbox"]')) return
        onOpen(run)
      }}
    >
      {selection.selectable && (
        <Checkbox
          className="mt-0.5 shrink-0"
          checked={selection.selected}
          onCheckedChange={(v) => selection.onSelectedChange(!!v)}
          aria-label={t('scans.card.select', undefined, {
            name: run.scan_name || t('scans.runs.scanRun'),
          })}
        />
      )}
      <div className="min-w-0 flex-1 space-y-1">
        <div
          data-slot="run-card-title"
          className="min-w-0 text-body font-medium [&_.truncate]:line-clamp-2 [&_.truncate]:whitespace-normal [&_.truncate]:break-words"
        >
          <RunScanCell run={run} />
        </div>
        <RunStateLine
          run={run}
          extra={
            run.intensity ? (
              <IntensityBadge intensity={run.intensity} className="shrink-0" />
            ) : undefined
          }
        />
        <MetaLine
          className="items-center"
          items={[
            <RunTasksText key="tasks" run={run} className="text-foreground" />,
            <span key="findings" className="tabular-nums">
              {t(
                'scans.runs.card.findings',
                '{count, plural, one {# finding} other {# findings}}',
                { count: run.total_findings }
              )}
            </span>,
          ]}
        />
        <MetaLine
          className="items-center"
          items={[
            who ? (
              <span key="who" title={who}>
                {who}
              </span>
            ) : null,
            <RelativeTime key="when" date={run.started_at || run.created_at} />,
            duration ? (
              <span key="duration" className="tabular-nums">
                {duration.text}
              </span>
            ) : null,
          ]}
        />
      </div>
    </div>
  )
}
