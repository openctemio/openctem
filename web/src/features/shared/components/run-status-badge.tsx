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
const RUN_STATE: Record<string, { state: HealthState; label: string }> = {
  queued: { state: 'queued', label: 'Queued' },
  pending: { state: 'queued', label: 'Pending' },
  running: { state: 'run', label: 'Running' },
  completed: { state: 'ok', label: 'Completed' },
  // Kept results but lost some work (a batch or a step failed).
  partial: { state: 'warn', label: 'Partial' },
  failed: { state: 'down', label: 'Failed' },
  timeout: { state: 'warn', label: 'Timed out' },
  canceled: { state: 'off', label: 'Canceled' },
  // Stopped part way and waiting for a person (an automation run at its change cap).
  paused: { state: 'warn', label: 'Paused' },
  // The trigger was refused before anything was dispatched (scope gate,
  // freeze window, no sensor, wildcard target...). Nothing ran.
  blocked: { state: 'paused', label: 'Blocked' },
}

/** A completed run with a conclusion: amber, in words. */
const RESULT_LABEL = {
  inconclusive: { i18n: 'scans.runStatus.completedInconclusive', label: 'Completed, inconclusive' },
  still_exposed_elsewhere: {
    i18n: 'scans.runStatus.completedExposedElsewhere',
    label: 'Completed, exposed at another path',
  },
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
  const resultKey =
    key === 'completed' && result
      ? RESULT_LABEL[(result.kind ?? '') as keyof typeof RESULT_LABEL]
      : undefined
  const known = resultKey
    ? { state: 'warn' as HealthState, label: resultKey.label }
    : RUN_STATE[key]
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
      state={known?.state ?? 'unknown'}
      value={key}
      label={
        label ??
        (resultKey
          ? t(resultKey.i18n, resultKey.label)
          : known
            ? t(`scans.runStatus.${key}`, known.label)
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
