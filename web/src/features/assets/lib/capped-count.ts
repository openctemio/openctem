/**
 * A list total the API caps at 10,000 (`total_capped`): shown as "10,000+" so a
 * number that stopped counting is never read as the exact one.
 */
export function formatTotal(
  total: number,
  capped: boolean | undefined,
  t: (key: string, fallback?: string, vars?: Record<string, string | number>) => string
): string {
  const n = total.toLocaleString()
  return capped ? t('assets.count.capped', '{count}+', { count: n }) : n
}
