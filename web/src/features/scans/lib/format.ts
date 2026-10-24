import { successRate } from './run-history'

/** "Oct 2, 03:41 PM"; "-" without a date. */
export function formatScanDate(dateString?: string): string {
  if (!dateString) return '-'
  return new Date(dateString).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

/** A run's duration in the largest two units (e.g. "3m 12s"); "-" without one. */
export function formatScanDuration(ms?: number): string {
  if (!ms) return '-'
  const seconds = Math.floor(ms / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  if (hours > 0) return `${hours}h ${minutes % 60}m`
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`
  return `${seconds}s`
}

/**
 * A scan's success rate over its settled runs, 0-100, or null below
 * MIN_RUNS_FOR_RATE settled runs. A partial run (finished with coverage gaps)
 * is a success; only failed runs count against it; blocked, canceled and
 * live runs are left out. The same rule as the list's run history
 * (run-history.ts), applied to the scan's lifetime counters.
 */
export function scanSuccessRate(config: {
  successful_runs: number
  failed_runs: number
  partial_runs?: number
}): number | null {
  return successRate(config.successful_runs ?? 0, config.partial_runs ?? 0, config.failed_runs ?? 0)
}
