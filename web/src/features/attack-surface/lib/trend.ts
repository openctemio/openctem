/**
 * Stat caption for an attack-surface trend count. The API counts what is NEW
 * in the window (never a net change), so the caption says so, zero included:
 * "0 new" is a fact, while a missing caption looked like missing data.
 */
export function newInWindow(count: number | undefined, days: number, noun = 'new'): string {
  return `${count ?? 0} ${noun} in the last ${days} days`
}
