'use client'

import type * as React from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { MetaLine, RelativeTime, RunStatusBadge, type MobileRowSelection } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanConfig } from '@/lib/api/scan-types'
import { lastRunOf, lastRunReason, scanTypeLabel } from '../lib/scan-status'
import { ScanApprovalBadge } from './approval/scan-approval-badge'
import { IntensityBadge } from './intensity-badge'
import { BlockedRunHint } from './last-run-cell'
import { RunHistory } from './run-history'

/**
 * A scan on a phone. One fact per element, in reading order, never a
 * label/value grid squeezed into two columns:
 *
 *   [ ] Name ............................ Last run state  [...]
 *       nuclei  Single check  Intrusive
 *       3 hours ago  30 runs  (run glyphs) 80%
 *       Why it was blocked, and where to fix it (blocked runs only)
 *
 * Every line is a wrapping flex row whose children have min-width 0, so a
 * long name, a long workflow name or a translated label wraps or is cut with
 * a tooltip; nothing can overflow into its neighbour.
 */
export function ScanMobileCard({
  config,
  selection,
  actions,
  onOpen,
  onOpenRun,
}: {
  config: ScanConfig
  selection: MobileRowSelection
  /** The row menu, the same one the table row has. */
  actions: React.ReactNode
  onOpen: (config: ScanConfig) => void
  onOpenRun: (runId: string) => void
}) {
  const { t } = useTranslation()
  const run = lastRunOf(config)
  const type = scanTypeLabel(config, t)
  const ts = run?.task_summary
  const waiting =
    !!run &&
    (run.status === 'running' || run.status === 'pending') &&
    !!ts &&
    ts.total > 0 &&
    ts.queued === ts.total
  return (
    <div
      data-slot="scan-card"
      data-state={selection.selected ? 'selected' : undefined}
      className="cursor-pointer px-3 py-3 hover:bg-muted/50 data-[state=selected]:bg-muted"
      onClick={(e) => {
        if (
          (e.target as HTMLElement).closest('button, a[href], [role="checkbox"], [role="menuitem"]')
        )
          return
        onOpen(config)
      }}
    >
      <div className="flex min-w-0 items-start gap-3">
        {selection.selectable && (
          <Checkbox
            className="mt-0.5 shrink-0"
            checked={selection.selected}
            onCheckedChange={(v) => selection.onSelectedChange(!!v)}
            aria-label={t('scans.card.select', undefined, { name: config.name })}
          />
        )}
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex min-w-0 items-start gap-2">
            <div
              data-slot="scan-card-title"
              className="flex min-w-0 flex-1 basis-32 flex-wrap items-center gap-x-2 gap-y-1"
            >
              <p className="min-w-0 break-words text-body font-medium">{config.name}</p>
              <ScanApprovalBadge status={config.approval_status} />
            </div>
            {run ? (
              <button
                type="button"
                data-slot="scan-card-status"
                className="shrink-0 rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                onClick={() => onOpenRun(run.id)}
                aria-label={t('scans.cell.openLatestRun', undefined, { status: run.status })}
              >
                <RunStatusBadge
                  status={waiting ? 'queued' : run.status}
                  progress={waiting ? undefined : run.progress}
                  label={waiting ? t('scans.cell.waitingForSensor') : undefined}
                  title={lastRunReason(run, t)}
                />
              </button>
            ) : (
              <span className="shrink-0 text-xs text-muted-foreground">
                {t('scans.cell.never')}
              </span>
            )}
            <div className="-my-1 shrink-0">{actions}</div>
          </div>
          <MetaLine
            className="items-center"
            items={[
              <span key="type" className="text-foreground" title={type.label}>
                {type.label}
              </span>,
              <span key="kind">
                {type.kind === 'workflow'
                  ? t('scans.scanType.workflow')
                  : t('scans.scanType.single')}
              </span>,
              config.intensity ? (
                <IntensityBadge key="intensity" intensity={config.intensity} />
              ) : null,
            ]}
          />
          <MetaLine
            className="items-center"
            items={[
              run ? <RelativeTime key="when" date={run.started_at ?? run.created_at} /> : null,
              <span key="runs" className="tabular-nums">
                {t(
                  config.total_runs === 1 ? 'scans.card.runsOne' : 'scans.card.runsMany',
                  undefined,
                  {
                    count: config.total_runs,
                  }
                )}
              </span>,
              config.total_runs > 0 ? <RunHistory key="history" runs={config.recent_runs} /> : null,
            ]}
          />
          <BlockedRunHint run={run} />
        </div>
      </div>
    </div>
  )
}
