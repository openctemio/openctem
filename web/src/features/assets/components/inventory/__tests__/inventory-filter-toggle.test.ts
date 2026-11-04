import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// The Assets inventory uses the same filter layout as Findings: the shared
// toggle (side panel from lg, sheet below) and the shared slot, not a fork.
const dir = join(__dirname, '..')
const page = readFileSync(join(dir, 'all-assets-inventory.tsx'), 'utf8')
const table = readFileSync(join(dir, 'inventory-table.tsx'), 'utf8')

describe('assets inventory filter layout', () => {
  it('toggles the shared side panel and keeps the sheet below lg', () => {
    expect(page).toContain('useFilterPanelOpen(FILTERS_OPEN_KEY)')
    expect(page).toContain('<FilterPanelSlot')
    expect(page).toContain('onOpenSheet: () => setFilterSheetOpen(true)')
    expect(page).toContain('filterToggle={filterToggle}')
    expect(page).not.toContain('<FilterButton')
  })
  it('passes the toggle through to the shared data table', () => {
    expect(table).toContain('filterToggle={filterToggle}')
  })
})
