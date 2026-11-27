/**
 * Governance: a "⋯" menu (a menu opened from a More icon) is the shared
 * `ActionMenu` (components/ui/action-menu.tsx), which shows it as an anchored
 * menu or, on a phone without room, as a bottom sheet with the object's name.
 * A hand-built `DropdownMenu` with a More icon misses that and the content
 * rules (destructive last, a reason on disabled items, icons all or none).
 * This test fails on a file with a `DropdownMenuTrigger` that holds a More
 * icon, unless the file is listed below.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '../../..')

/** Menus with a More icon that are not action menus, with the reason. */
const ALLOW: Record<string, string> = {
  'components/layout/breadcrumb-nav.tsx': 'navigation: the folded breadcrumb levels',
  'components/ui/markdown-editor.tsx':
    'formatting commands of the editor toolbar; keeps the editor focus',
  'features/shared/components/data-table/data-table.tsx':
    'the phone list menu holds checkbox items (choices, not actions)',
}

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx') && !name.includes('.test.')) yield p
  }
}

const MORE_ICON = /<(MoreHorizontal|MoreVertical|Ellipsis)\b/
const TRIGGER = /<DropdownMenuTrigger\b[\s\S]*?<\/DropdownMenuTrigger>/g

function handBuiltMoreMenus(): Set<string> {
  const found = new Set<string>()
  for (const file of tsxFiles(SRC)) {
    const rel = relative(SRC, file)
    // The kit's own files define the pieces.
    if (rel.startsWith('components/ui/') && !(rel in ALLOW)) continue
    const text = readFileSync(file, 'utf8')
    for (const m of text.matchAll(TRIGGER)) {
      if (MORE_ICON.test(m[0])) {
        found.add(rel)
        break
      }
    }
  }
  return found
}

describe('"⋯" menus', () => {
  const found = handBuiltMoreMenus()

  it('use ActionMenu', () => {
    const offenders = [...found].filter((rel) => !(rel in ALLOW))
    expect(offenders).toEqual([])
  })

  it('lists only files that still need it', () => {
    const stale = Object.keys(ALLOW).filter((rel) => !found.has(rel))
    expect(stale).toEqual([])
  })
})
