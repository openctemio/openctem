import type { HealthState } from '@/lib/health-colors'

/**
 * How the scan list reads a scan's run history: one rule for the run dots,
 * the success rate and its tooltip.
 *
 * A run counts as a success when it did its job and kept results:
 * completed, or partial (finished with coverage gaps: some hosts were not
 * reachable or some work was lost). A run counts as a failure only when the
 * sensor, the tool or the platform failed it (failed, timed out). A gap on
 * the target side (a host switched off, a name gone from DNS) is a fact about
 * the target, not a scan failure (research/259 R3), so it never lowers the
 * rate; the dot still shows it.
 *
 * Runs that never started are not counted: blocked (refused before dispatch,
 * a person has to fix the scan or its scope) and canceled (stopped by a
 * person). Runs still going are not counted either.
 */

export type RunOutcome = 'ok' | 'gaps' | 'failed' | 'blocked' | 'canceled' | 'live' | 'unknown'

/** Below this many counted runs the rate is not meaningful: show "-". */
export const MIN_RUNS_FOR_RATE = 3

export function runOutcome(status: string): RunOutcome {
  switch (status) {
    case 'completed':
      return 'ok'
    case 'partial':
      return 'gaps'
    case 'failed':
    case 'timeout':
      return 'failed'
    case 'blocked':
      return 'blocked'
    case 'canceled':
    case 'cancelled':
      return 'canceled'
    case 'running':
    case 'pending':
    case 'queued':
      return 'live'
    default:
      return 'unknown'
  }
}

/** The machine-health glyph of a run state: the same one RunStatusBadge draws. */
export const RUN_OUTCOME_HEALTH: Record<RunOutcome, HealthState> = {
  ok: 'ok',
  gaps: 'warn',
  failed: 'down',
  // Nothing ran: a pause ring, not a failure. The list says why next to it.
  blocked: 'paused',
  canceled: 'off',
  live: 'run',
  unknown: 'unknown',
}

export interface RunHistorySummary {
  ok: number
  gaps: number
  failed: number
  blocked: number
  canceled: number
  live: number
  /** Runs the rate is computed over: ok + gaps + failed. */
  counted: number
  /** 0-100, or null below MIN_RUNS_FOR_RATE counted runs. */
  rate: number | null
}

/** Successes over counted runs; null when there are too few to say. */
export function successRate(ok: number, gaps: number, failed: number): number | null {
  const counted = ok + gaps + failed
  if (counted < MIN_RUNS_FOR_RATE) return null
  return Math.round(((ok + gaps) / counted) * 100)
}

export function summarizeRuns(runs: { status: string }[]): RunHistorySummary {
  const s = { ok: 0, gaps: 0, failed: 0, blocked: 0, canceled: 0, live: 0 }
  for (const r of runs) {
    const o = runOutcome(r.status)
    if (o !== 'unknown') s[o] += 1
  }
  return {
    ...s,
    counted: s.ok + s.gaps + s.failed,
    rate: successRate(s.ok, s.gaps, s.failed),
  }
}
