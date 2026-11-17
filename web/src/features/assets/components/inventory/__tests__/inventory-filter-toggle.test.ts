import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// The Assets inventory has one filter entry per width and no docked panel:
// Add filter (a popover from 768 px), and on a phone the shared Filters
// button that opens every facet in the shared sheet.
const dir = join(__dirname, '..')
const page = readFileSync(join(dir, 'all-assets-inventory.tsx'), 'utf8')
const table = readFileSync(join(dir, 'inventory-table.tsx'), 'utf8')

describe('assets inventory filter layout', () => {
  it('has no docked filter panel; the phone button opens the shared sheet', () => {
    expect(page).not.toContain('FilterPanelSlot')
    expect(page).not.toContain('useFilterPanelOpen')
    expect(page).toContain('<InventoryAddFilter')
    expect(page).toContain('<FilterSheet')
    expect(page).toContain('sheetOnly: true')
    expect(page).toContain('onOpenSheet: () => setFilterSheetOpen(true)')
    expect(page).toContain('filterToggle={filterToggle}')
    expect(page).not.toContain('<FilterButton')
  })
  it('passes the toggle through to the shared data table', () => {
    expect(table).toContain('filterToggle={filterToggle}')
  })

  it('reads type attribute labels in the viewer language', () => {
    // propertyLabel(key) alone is always English: the locale must be passed.
    expect(table).not.toMatch(/propertyLabel\(attribute\.key\)/)
    expect(page).not.toMatch(/propertyLabel\(attribute\.key\)/)
    expect(table).toContain('propertyLabel(attribute.key, locale)')
  })
})
