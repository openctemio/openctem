/**
 * Guard: numbers and dates are written in the reader's language through the
 * format helpers (`@/lib/app-locale`, `@/lib/format-metric`,
 * `@/lib/format-date`), never with the browser's or a hard-coded locale.
 * A raw `toLocaleString()` printed "12840" or "Nov 18, 2026" on a Vietnamese
 * page.
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import {
  formatDate,
  formatDateTime,
  formatNumber,
  formatTime,
  setAppLocale,
} from '@/lib/app-locale'

const ROOTS = [join(process.cwd(), 'src'), join(process.cwd(), 'console', 'src')]
const HELPERS = new Set([
  'src/lib/app-locale.ts',
  'src/lib/format-metric.ts',
  'src/lib/format-date.ts',
])

/**
 * Machine formats that must not follow the reader: time-zone arithmetic reads
 * the parts of an en-US string, and en-CA gives a YYYY-MM-DD date.
 */
const FIXED_LOCALE_ALLOWED = new Set([
  'src/features/scans/lib/zoned-time.ts',
  'src/features/scan-windows/lib/schedule.ts',
  'src/features/scans/components/new-scan/schedule-step.tsx',
])

function sources(): string[] {
  const out: string[] = []
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name)
      if (statSync(full).isDirectory()) {
        if (!['__tests__', 'node_modules', '.next'].includes(name)) walk(full)
      } else if (/\.tsx?$/.test(name) && !/\.(test|spec)\.tsx?$/.test(name)) out.push(full)
    }
  }
  for (const root of ROOTS) walk(root)
  return out
}

describe('locale formatting', () => {
  const files = sources().map((f) => ({
    rel: relative(process.cwd(), f),
    src: readFileSync(f, 'utf8'),
  }))

  it('has no raw toLocaleString/toLocaleDateString/toLocaleTimeString outside the helpers', () => {
    const bad = files
      .filter(({ rel }) => !HELPERS.has(rel))
      .flatMap(({ rel, src }) =>
        src
          .split('\n')
          .map((line, i) => [line, i] as const)
          .filter(([line]) => /\.toLocale(Date|Time)?String\(/.test(line))
          .map(([, i]) => `${rel}:${i + 1}`)
      )
    expect(bad).toEqual([])
  })

  it('never formats with a hard-coded language', () => {
    const bad = files
      .filter(({ rel }) => !HELPERS.has(rel) && !FIXED_LOCALE_ALLOWED.has(rel))
      .flatMap(({ rel, src }) =>
        [...src.matchAll(/Intl\.\w+Format\(\s*['"](en|en-US|en-GB|vi)['"]/g)].map(
          (m) => `${rel}: ${m[0]}`
        )
      )
    expect(bad).toEqual([])
  })

  it('writes numbers and dates in the page language', () => {
    const d = new Date('2026-11-18T09:05:00Z')
    setAppLocale('en')
    expect(formatNumber(12840)).toBe('12,840')
    expect(formatDate(d, { dateStyle: 'medium', timeZone: 'UTC' })).toBe('Nov 18, 2026')
    setAppLocale('vi')
    expect(formatNumber(12840)).toBe('12.840')
    const vi = formatDate(d, { dateStyle: 'medium', timeZone: 'UTC' })
    expect(vi).not.toMatch(/Nov/)
    expect(vi).toContain('2026')
    expect(formatTime(d, { timeStyle: 'short', timeZone: 'UTC' })).toBe('09:05')
    expect(formatDateTime(null)).toBe('—')
    setAppLocale('en')
  })
})
