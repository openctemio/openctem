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

/**
 * Files whose "⋯" menu moves in a follow-up change (or in a change that owns
 * the file). Remove an entry when its menu moves; never add one for new code.
 */
const PENDING = new Set([
  'features/access-control/components/role-detail-sheet.tsx',
  'features/activity/components/activity-items.tsx',
  'features/assets/components/asset-owners-tab.tsx',
  'features/assets/components/inventory/inventory-table.tsx',
  'features/assets/components/relationships/related-assets-list.tsx',
  'features/dashboards/components/dashboard-home.tsx',
  'features/dashboards/editor/dashboard-editor.tsx',
  'features/findings/components/detail/finding-header.tsx',
  'features/findings/components/lifecycle/sub-status-lanes.tsx',
  'features/pentest/components/campaign-detail-sheet.tsx',
  'features/pentest/components/steps-editor.tsx',
  'features/remediation/components/campaign-detail.tsx',
  'features/remediation-hub/components/task-detail.tsx',
  'features/repositories/components/repository-workspace.tsx',
  'features/scm-connections/components/scm-connection-card.tsx',
  'features/vulnerabilities/components/actions/vuln-actions-menu.tsx',
])

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
    const offenders = [...found].filter((rel) => !(rel in ALLOW) && !PENDING.has(rel))
    expect(offenders).toEqual([])
  })

  it('lists only files that still need it', () => {
    const stale = [...Object.keys(ALLOW), ...PENDING].filter((rel) => !found.has(rel))
    expect(stale).toEqual([])
  })
})
