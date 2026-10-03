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
 * Share of a scan's FINISHED runs that succeeded, 0–100, or null before any
 * run finished. Runs still going are in total_runs but are neither a success
 * nor a failure yet, so they are left out.
 */
export function scanSuccessRate(config: {
  successful_runs: number
  failed_runs: number
}): number | null {
  const finished = (config.successful_runs ?? 0) + (config.failed_runs ?? 0)
  if (finished <= 0) return null
  return Math.round(((config.successful_runs ?? 0) / finished) * 100)
}
