import type { PillTone } from '@/features/shared/components/tone-pill'

/** Tone of a check level: 0 ok, 1 warning, 2 critical. */
export function levelTone(level: number): PillTone {
  if (level >= 2) return 'destructive'
  if (level === 1) return 'warning'
  return 'success'
}

export type LevelKey = 'ok' | 'warning' | 'critical'

export function levelKey(level: number): LevelKey {
  if (level >= 2) return 'critical'
  if (level === 1) return 'warning'
  return 'ok'
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']

/** Binary size with one decimal above KiB. */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '-'
  let v = n
  let i = 0
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024
    i++
  }
  return `${i === 0 ? v : v.toFixed(1)} ${UNITS[i]}`
}

/** Whole days until a certificate expires (negative once expired). */
export function daysLeft(seconds: number | undefined): number | null {
  return seconds === undefined ? null : Math.floor(seconds / 86400)
}

/** Backup age as hours, for the 26 hour rule. */
export function hoursAgo(seconds: number | undefined): number | null {
  return seconds === undefined ? null : Math.floor(seconds / 3600)
}
