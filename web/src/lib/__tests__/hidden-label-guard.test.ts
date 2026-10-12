/**
 * Guard: a button label hidden on phones stays readable by screen readers.
 *
 * `className="hidden sm:inline"` on a button's text leaves an icon-only button
 * with no accessible name on a phone (display: none drops the text from the
 * accessibility tree). Use `className="sr-only sm:not-sr-only"`: the text is
 * visually hidden on phones but still names the button.
 *
 * Listed files keep the old class because they render their own phone label
 * next to it (a `sm:hidden` or `sr-only sm:hidden` span).
 */
import fs from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

const SRC_ROOT = path.resolve(__dirname, '../..')

const REVIEWED = new Set([
  'components/notification-bell.tsx',
  'features/scans/components/scan-runs-tab.tsx',
])

function tsxFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) return e.name === 'node_modules' ? [] : tsxFiles(p)
    return e.name.endsWith('.tsx') ? [p] : []
  })
}

describe('hidden button labels', () => {
  it('uses sr-only sm:not-sr-only instead of hidden sm:inline', () => {
    const offenders = tsxFiles(SRC_ROOT)
      .map((f) => path.relative(SRC_ROOT, f).split(path.sep).join('/'))
      .filter((rel) => !REVIEWED.has(rel))
      .filter((rel) =>
        fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8').includes('className="hidden sm:inline"')
      )
    expect(offenders).toEqual([])
  })
})
