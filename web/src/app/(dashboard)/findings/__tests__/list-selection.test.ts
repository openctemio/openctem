/**
 * The findings list's selection contract, read from the page source: the
 * selection belongs to one page of one filtered, sorted list, and bulk assign
 * goes through post() so a step-up challenge is answered by the shared dialog.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const page = readFileSync(join(__dirname, '..', 'page.tsx'), 'utf8')

describe('findings list selection', () => {
  it('scopes the selection to page, page size and every filter, search, sort and view', () => {
    expect(page).toMatch(
      /const selectionScope = `\$\{pagination\.pageIndex\}\|\$\{pagination\.pageSize\}\|\$\{filterKey\}`/
    )
    for (const part of ['debouncedSearch', 'sortParam', 'viewParam', 'groupParam'])
      expect(page.slice(page.indexOf('const filterKey'), page.indexOf('].join(')), part).toContain(
        part
      )
  })

  it('hands the scope to the flat table and the grouped views', () => {
    expect(page).toContain('resetSelectionKey={`${selectionEpoch}|${selectionScope}`}')
    expect(page).toContain('resetSelectionKey: `${selectionEpoch}|${selectionScope}`')
  })

  it('assigns in bulk through post(), not a bare fetch', () => {
    expect(page).not.toContain('csrfFetch')
    expect(page).toMatch(/post<BulkFindingResult>\('\/api\/v1\/findings\/bulk\/assign'/)
  })

  it('opens a finding from a click anywhere on the row', () => {
    expect(page).toContain('onRowClick={handleRowClick}')
  })
})
