/**
 * Times and dates follow the console language. A relative time written with
 * date-fns without a `locale` reads "5 days ago" in the Vietnamese console;
 * a bare `toLocaleDateString()` follows the browser, not the console.
 *
 * - Every `formatDistanceToNow` / `formatDistance` / `formatDistanceStrict`
 *   call passes an options object with `locale` (or use `<RelativeTime>`,
 *   which reads the language itself, or `formatRelative` from lib/format-date).
 * - Calls of `toLocaleDateString()` / `toLocaleTimeString()` with no locale
 *   may only go down (use `formatLocalized` / `formatCalendarDate` /
 *   `formatAbsoluteTime` with `useTranslation().locale`).
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const SRC = join(__dirname, '..', '..')
const SKIP_DIR = new Set(['__tests__', '__mocks__', 'generated', 'dictionaries'])
const DISTANCE = new Set(['formatDistanceToNow', 'formatDistance', 'formatDistanceStrict'])

// Lower this when you migrate a call; it may never go up.
const MAX_BARE_TO_LOCALE = 68

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return SKIP_DIR.has(name) ? [] : sources(path)
    if (/\.(test|spec|stories)\.tsx?$/.test(name) || name.endsWith('.d.ts')) return []
    return /\.tsx?$/.test(name) ? [path] : []
  })
}

export function distanceCallsWithoutLocale(fileName: string, source: string): number[] {
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const lines: number[] = []
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      if (DISTANCE.has(node.expression.text)) {
        const opts = node.arguments[node.arguments.length - 1]
        const hasLocale =
          opts !== undefined &&
          ts.isObjectLiteralExpression(opts) &&
          opts.properties.some(
            (p) =>
              (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) &&
              ts.isIdentifier(p.name) &&
              p.name.text === 'locale'
          )
        if (!hasLocale) lines.push(sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return lines
}

describe('dates follow the console language', () => {
  const files = sources(SRC).map((f) => [relative(SRC, f), readFileSync(f, 'utf8')] as const)

  it('passes a locale to every date-fns distance call', () => {
    const bad = files.flatMap(([f, s]) => distanceCallsWithoutLocale(f, s).map((l) => `${f}:${l}`))
    expect(bad, 'use <RelativeTime>, or pass { locale: dateFnsLocaleFor(locale) }').toEqual([])
  })

  it('does not add bare toLocaleDateString() / toLocaleTimeString() calls', () => {
    const n = files.reduce(
      (sum, [, s]) => sum + (s.match(/\.toLocale(Date|Time)String\(\)/g)?.length ?? 0),
      0
    )
    expect(n, 'format with useTranslation().locale (lib/format-date, lib/format-metric)').toBe(
      MAX_BARE_TO_LOCALE
    )
  })

  it('finds a distance call without a locale', () => {
    const src = `
      formatDistanceToNow(d, { addSuffix: true })
      formatDistanceToNow(d, { addSuffix: true, locale })
      formatDistance(a, b, { locale: x })
      formatDistanceToNow(d)
    `
    expect(distanceCallsWithoutLocale('x.ts', src)).toEqual([2, 5])
  })
})
