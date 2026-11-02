/**
 * Why an uncovered asset is uncovered (the API's coverage_cause filter, in
 * its precedence order).
 */
export const COVERAGE_CAUSES = [
  'no_sensor',
  'platform_failure',
  'paused',
  'target_unreachable',
  'never_run',
  'overdue',
  'out_of_scope',
  'other',
] as const
export type CoverageCause = (typeof COVERAGE_CAUSES)[number]

export function isCoverageCause(v: string | null | undefined): v is CoverageCause {
  return !!v && (COVERAGE_CAUSES as readonly string[]).includes(v)
}
