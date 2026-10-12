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
 * Share of a scan's SETTLED runs that fully succeeded, 0–100, or null before
 * any run settled. Settled = succeeded + partial + failed. Runs still going
 * and canceled runs are in total_runs but are neither, so they are left out.
 * A partial run (results kept, some work lost) is settled but not a success.
 * The one formula every scan page uses.
 */
export function scanSuccessRate(config: {
  successful_runs: number
  failed_runs: number
  partial_runs?: number
}): number | null {
  const ok = config.successful_runs ?? 0
  const settled = ok + (config.partial_runs ?? 0) + (config.failed_runs ?? 0)
  if (settled <= 0) return null
  return Math.round((ok / settled) * 100)
}
