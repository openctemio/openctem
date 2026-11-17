/**
 * Governance: a menu is as wide as its content (the kit's floor and ceiling in
 * components/ui/dropdown-menu.tsx: at least the trigger or 128 px, 160 px with
 * icons, at most 360 px or the screen less its gutters). A fixed width on a
 * menu, popover or select list padded short lists out to 256 px or more: a
 * two-item status menu opened as a wide panel. This test fails on a width
 * class (`w-*`, `min-w-*`, `max-w-*`) on one of them unless the file and
 * element are reviewed below, with the reason its content needs the width.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '../../..')

/** `<file> <Element>` → why the content needs its own width. */
const REVIEWED: Record<string, string> = {
  // Menus
  'app/(dashboard)/settings/pentest/report-templates/page.tsx DropdownMenuContent':
    'each item has a hint line; a fixed measure wraps the hints',
  'features/assets/components/inventory/monitoring-state-control.tsx DropdownMenuContent':
    'each decision has an explanation line; a fixed measure wraps them',
  'features/dashboards/components/dashboard-switcher.tsx DropdownMenuContent':
    'a picker with a search field keeps its width while the list filters',
  'components/layout/header-create-menu.tsx DropdownMenuContent': 'shell design: create menu 232',
  'components/layout/nav-group.tsx DropdownMenuContent': 'shell design: sidebar flyout',
  'components/layout/nav-group.tsx DropdownMenuSubContent': 'shell design: sidebar flyout',
  'components/layout/sidebar-footer-links.tsx DropdownMenuContent': 'shell design: help menu',
  'components/profile-dropdown.tsx DropdownMenuContent': 'shell design: account menu 256',
  // Popovers: panels of text, forms and search pickers, not lists of actions
  'components/graph-page/graph-page.tsx PopoverContent': 'explanation text needs a reading measure',
  'components/layout/team-switcher.tsx PopoverContent': 'shell design: organization switcher',
  'components/notification-bell.tsx PopoverContent': 'shell design: notifications panel',
  'features/activity/components/comment-reactions.tsx PopoverContent':
    'w-auto: sized by its content already',
  'features/assets/components/service-cells/label-chips.tsx PopoverContent':
    'a form with one field',
  'features/assets/components/service-cells/more-chip.tsx PopoverContent':
    'w-auto with the 360 px ceiling: sized by its content',
  'features/assets/components/service-cells/surface-facts.tsx PopoverContent':
    'a fact sheet with long values',
  'features/findings/components/create-finding-dialog.tsx PopoverContent':
    'a combobox as wide as its field',
  'features/findings/components/detail/sla-why-this-date.tsx PopoverContent':
    'explanation text needs a reading measure',
  'features/pentest/components/campaign-picker.tsx PopoverContent': 'a picker with a search field',
  'features/pentest/components/classification-pickers.tsx PopoverContent':
    'a picker with a search field',
  'features/pentest/components/finding-editor/finding-action-bar.tsx PopoverContent':
    'a two-column shortcut list',
  'features/pentest/components/targets-field.tsx PopoverContent': 'a picker with a search field',
  'features/remediation-hub/components/owner-combobox.tsx PopoverContent':
    'a picker with a search field',
  'features/scan-workflows/components/readiness-badge.tsx PopoverContent':
    'explanation text needs a reading measure',
  'features/scans/components/timezone-select.tsx PopoverContent': 'a picker with a search field',
  'features/shared/components/multi-select.tsx PopoverContent': 'a picker with a search field',
  'features/tools/components/tool-availability.tsx PopoverContent':
    'a list of sensors with details',
  'app/(dashboard)/(scoping)/business-units/page.tsx PopoverContent':
    'a combobox as wide as its field',
  'features/assets/components/asset-owners-tab.tsx PopoverContent':
    'a combobox as wide as its field',
  'features/assets/components/inventory/inventory-bulk-bar.tsx PopoverContent':
    'a combobox as wide as its field',
  'features/query/components/query-input.tsx PopoverContent':
    'suggestions under a query field, capped at 24rem',
  'features/shared/components/filter-chips-row.tsx PopoverContent':
    'w-auto with a ceiling: sized by its content',
}

/**
 * Menus whose padding width goes in a change that owns the file (the list
 * toolbar, saved views, the data table). Remove an entry with its width;
 * never add one for new code.
 */
const PENDING = new Set<string>([])

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx') && !name.includes('.test.')) yield p
  }
}

const OPENING_TAG =
  /<(DropdownMenuContent|DropdownMenuSubContent|SelectContent|PopoverContent)\b([\s\S]*?)>/g
const WIDTH_CLASS = /(?:^|[\s'"`{(])(?:[a-z0-9-]+:)*-?(?:min-w|max-w|w)-[^\s'"`})]+/

function widthKeys(): Map<string, string> {
  const found = new Map<string, string>()
  for (const file of tsxFiles(SRC)) {
    const rel = relative(SRC, file)
    if (rel.startsWith('components/ui/')) continue
    const text = readFileSync(file, 'utf8')
    for (const m of text.matchAll(OPENING_TAG)) {
      if (!WIDTH_CLASS.test(m[2])) continue
      const line = text.slice(0, m.index).split('\n').length
      found.set(`${rel} ${m[1]}`, `${rel}:${line} <${m[1]}>`)
    }
  }
  return found
}

describe('floating widths', () => {
  const found = widthKeys()

  it('are left to the content unless the content needs one', () => {
    const offenders = [...found]
      .filter(([key]) => !(key in REVIEWED) && !PENDING.has(key))
      .map(([, where]) => where)
    expect(offenders).toEqual([])
  })

  it('lists only elements that still set a width', () => {
    const stale = [...Object.keys(REVIEWED), ...PENDING].filter((key) => !found.has(key))
    expect(stale).toEqual([])
  })
})
