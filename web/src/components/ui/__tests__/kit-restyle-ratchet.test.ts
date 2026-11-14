/**
 * Pages do not restyle kit controls ("Sizes" in web/docs/ui-style-contract.md):
 * a control's height, width, padding, text size and colour come from the
 * tokens in src/styles/theme.css through the kit component in
 * src/components/ui and its variants. A page that needs another look adds a
 * variant to the kit instead. Controls of one row then always match: the
 * page-rhythm probe (e2e/helpers/page-anatomy.ts, probeRowMix) measures it.
 *
 * Today's overrides are the baseline (scripts/kit-restyle-debt.json, counted
 * per file by scripts/kit-restyle.mjs); it may only go down:
 * - a file that is not listed may add none;
 * - a listed file may not go above its count;
 * - a listed file that went below its count must lower it.
 * Regenerate after a clean-up (the diff is reviewed):
 *   UPDATE_KIT_RESTYLE_DEBT=1 npx vitest run src/components/ui/__tests__/kit-restyle-ratchet.test.ts
 */
import { writeFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { findKitRestyles, restyleKind } from '../../../../scripts/kit-restyle.mjs'
import debt from '../../../../scripts/kit-restyle-debt.json'

const WEB = path.resolve(__dirname, '../../../..')
const DEBT_FILE = path.join(WEB, 'scripts/kit-restyle-debt.json')
const baseline = debt as Record<string, number>

describe('kit controls are not restyled in page code', () => {
  const found = findKitRestyles(WEB) as Map<
    string,
    { line: number; control: string; kinds: string[]; classes: string[] }[]
  >

  if (process.env.UPDATE_KIT_RESTYLE_DEBT === '1') {
    it('writes the baseline', () => {
      const next = Object.fromEntries(
        [...found.entries()]
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([file, hits]) => [file, hits.length])
      )
      writeFileSync(DEBT_FILE, JSON.stringify(next, null, 2) + '\n')
    })
    return
  }

  it('adds no size, padding, text-size or colour override on a kit control', () => {
    const grown = [...found.entries()]
      .filter(([file, hits]) => hits.length > (baseline[file] ?? 0))
      .map(
        ([file, hits]) =>
          `${file}: ${hits.length} (allowed ${baseline[file] ?? 0})\n` +
          hits
            .map((h) => `  ${h.line} <${h.control}> ${h.kinds.join(', ')}: ${h.classes.join(' ')}`)
            .join('\n')
      )
    expect(grown, grown.join('\n')).toEqual([])
  }, 60_000)

  it('keeps the baseline tight (lower it when a file got cleaner)', () => {
    const shrunk = Object.entries(baseline)
      .filter(([file, n]) => (found.get(file)?.length ?? 0) < n)
      .map(([file, n]) => `${file}: ${found.get(file)?.length ?? 0} (baseline ${n})`)
    expect(
      shrunk,
      'Run UPDATE_KIT_RESTYLE_DEBT=1 npx vitest run src/components/ui/__tests__/kit-restyle-ratchet.test.ts'
    ).toEqual([])
  })
})

describe('restyle classifier', () => {
  it.each([
    ['h-9', false, 'height'],
    ['max-md:h-11', false, 'height'],
    ['size-8', false, 'size'],
    ['w-8', true, 'width'],
    ['px-2', false, 'padding'],
    ['text-xs', false, 'text size'],
    ['text-[11px]', false, 'text size'],
    ['text-destructive', false, 'colour'],
    ['hover:bg-muted', false, 'colour'],
  ])('%s is a %s override', (token, icon, kind) => {
    expect(restyleKind(token, icon)).toBe(kind)
  })

  it.each([
    'w-full',
    'w-40',
    'gap-2',
    'ms-auto',
    'shrink-0',
    'text-start',
    'truncate',
    'pointer-events-none',
  ])('%s is layout, not a restyle', (token) => {
    expect(restyleKind(token, false)).toBeNull()
  })
})
