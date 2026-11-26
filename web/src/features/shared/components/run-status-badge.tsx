'use client'

import { HealthStatus } from '@/components/ui/health-status'
import { useTranslation } from '@/context/i18n-provider'
import type { HealthState } from '@/lib/health-colors'
import { humanizeIdentifier } from '@/lib/humanize-identifier'

/**
 * Canonical label for scan / workflow RUN status: a HealthStatus (icon and
 * plain text), so every run reads the same everywhere and nothing spins. Each
 * state keeps its own icon, word and translation:
 * queued and pending wait for a sensor, running is a static half circle,
 * completed is ok, partial and timeout need attention, failed is down,
 * blocked is a pause ring (nothing ran; a person has to change the scan or its
 * scope, which is a decision, not a machine failure), canceled is off.
 */
const RUN_STATE: Record<string, HealthState> = {
  queued: 'queued',
  pending: 'queued',
  running: 'run',
  completed: 'ok',
  // Kept results but lost some work (a batch or a step failed).
  partial: 'warn',
  failed: 'down',
  timeout: 'warn',
  canceled: 'off',
  // Stopped part way and waiting for a person (an automation run at its change cap).
  paused: 'warn',
  // The trigger was refused before anything was dispatched (scope gate,
  // freeze window, no sensor, wildcard target...). Nothing ran.
  blocked: 'paused',
}

/** The words of each run state (the catalog has them under scans.runStatus). */
function runLabels(t: ReturnType<typeof useTranslation>['t']): Record<string, string> {
  return {
    queued: t('components.shared.runStatus.queued', 'Queued'),
    pending: t('scans.runStatus.pending', 'Pending'),
    running: t('scans.runStatus.running', 'Running'),
    completed: t('scans.runStatus.completed', 'Completed'),
    partial: t('scans.runStatus.partial', 'Partial'),
    failed: t('scans.runStatus.failed', 'Failed'),
    timeout: t('scans.runStatus.timeout', 'Timed out'),
    canceled: t('scans.runStatus.canceled', 'Canceled'),
    paused: t('scans.runStatus.paused', 'Paused'),
    blocked: t('scans.runStatus.blocked', 'Blocked'),
  }
}

/**
 * One run's state, everywhere a run state is shown. `progress` (0-100) is
 * added to a live run's label ("Running 42%"); `title` is the hover text
 * (e.g. why a blocked run was refused), rendered as plain text.
 */
export function RunStatusBadge({
  status,
  className,
  progress,
  title,
  label,
  note,
  result,
}: {
  status: string
  className?: string
  progress?: number
  title?: string
  /** Replaces the status word ("Waiting for a sensor" for a run no sensor picked up). */
  label?: string
  /**
   * What the run did not scan because of the targets themselves ("3
   * unreachable"), shown after the status. It never changes the status.
   */
  note?: string | null
  /**
   * What a completed run concluded when that is more than "done" (a retest
   * that was inconclusive, or found the exposure at another path). The run
   * did its work, so it is amber and never Failed.
   */
  result?: { kind?: string; code?: string } | null
}) {
  const { t } = useTranslation()
  // Normalize the two spellings the backends use.
  const key = status === 'cancelled' ? 'canceled' : status
  // A completed run with a conclusion: amber, in words.
  const resultLabel =
    key === 'completed' && result
      ? {
          inconclusive: t('scans.runStatus.completedInconclusive', 'Completed, inconclusive'),
          still_exposed_elsewhere: t(
            'scans.runStatus.completedExposedElsewhere',
            'Completed, exposed at another path'
          ),
        }[result.kind ?? '']
      : undefined
  const state: HealthState | undefined = resultLabel ? 'warn' : RUN_STATE[key]
  const live = key === 'running' || key === 'pending' || key === 'queued'
  const pct =
    live && typeof progress === 'number' && Number.isFinite(progress)
      ? Math.max(0, Math.min(100, Math.round(progress)))
      : null
  const detail = [pct !== null ? `${pct}%` : null, note || null].filter(
    (d): d is string => d !== null
  )
  return (
    <HealthStatus
      state={state ?? 'unknown'}
      value={key}
      label={
        label ??
        (resultLabel
          ? resultLabel
          : state
            ? runLabels(t)[key]
            : status
              ? humanizeIdentifier(status)
              : t('labels.health.unknown', 'Unknown'))
      }
      detail={detail.length ? detail : undefined}
      title={title}
      className={className}
    />
  )
}
