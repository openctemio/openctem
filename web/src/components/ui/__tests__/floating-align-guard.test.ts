/**
 * Governance: a menu, popover or select list below or above its trigger lines
 * up with the trigger's start edge, or its end edge when the start would
 * cross the room it has (the kit decides, `chooseAlign` in
 * components/ui/floating.ts). A fixed
 * `align="start"` or `align="end"` breaks that on a phone, where the same
 * trigger moves from the right of a row to the left when the row wraps; this
 * test fails when one comes back. Popups beside their trigger (side left or
 * right) and `align="center"` are not covered.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '../../..')

/**
 * Placement fixed by the shell design (phone top-bar sheets end under their
 * trigger, the organization switcher, breadcrumbs and sidebar menus).
 */
const DESIGN_FIXED = new Set([
  'components/layout/breadcrumb-nav.tsx',
  'components/layout/header-create-menu.tsx',
  'components/layout/sidebar-footer-links.tsx',
  'components/layout/team-switcher.tsx',
  'components/layout/top-nav.tsx',
  'components/notification-bell.tsx',
  'components/profile-dropdown.tsx',
])

/**
 * Files other in-flight changes are rewriting (list toolbar, filter chips,
 * bulk bars, the findings page menus). Remove an entry once its fixed
 * alignment is gone; never add one for new code.
 */
const PENDING = new Set([
  'app/(dashboard)/findings/page.tsx',
  'features/saved-views/components/saved-views-menu.tsx',
  'features/shared/components/filter-chips-row.tsx',
  'features/shared/components/filter-select.tsx',
])

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx')) yield p
  }
}

const OPENING_TAG = /<(DropdownMenuContent|PopoverContent|SelectContent)\b([^>]*?)>/g

describe('floating alignment', () => {
  it('is left to the kit for popups above or below their trigger', () => {
    const offenders: string[] = []
    for (const file of tsxFiles(SRC)) {
      const rel = relative(SRC, file)
      if (rel.startsWith('components/ui/') || DESIGN_FIXED.has(rel) || PENDING.has(rel)) continue
      const text = readFileSync(file, 'utf8')
      for (const m of text.matchAll(OPENING_TAG)) {
        const attrs = m[2]
        if (/\bside="(left|right)"/.test(attrs)) continue
        if (/\balign="(start|end)"/.test(attrs)) {
          const line = text.slice(0, m.index).split('\n').length
          offenders.push(`${rel}:${line} <${m[1]}>`)
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('lists only files that still need it', () => {
    const stale: string[] = []
    for (const rel of [...DESIGN_FIXED, ...PENDING]) {
      const text = readFileSync(join(SRC, rel), 'utf8')
      const fixed = [...text.matchAll(OPENING_TAG)].some(
        (m) => !/\bside="(left|right)"/.test(m[2]) && /\balign="(start|end)"/.test(m[2])
      )
      if (!fixed) stale.push(rel)
    }
    expect(stale).toEqual([])
  })
})
