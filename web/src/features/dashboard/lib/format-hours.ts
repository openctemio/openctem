/**
 * A duration in hours as the dashboards show it: minutes under an hour, hours
 * under a day, days with one decimal above. Null (nothing measured) is "—",
 * never 0m. One formatter, so the same MTTR reads the same on every page.
 */
export function formatHours(hours: number | undefined | null): string {
  if (hours === undefined || hours === null || Number.isNaN(hours)) return '—'
  if (hours < 1) return `${(hours * 60).toFixed(0)}m`
  if (hours < 24) return `${hours.toFixed(1)}h`
  return `${(hours / 24).toFixed(1)}d`
}
