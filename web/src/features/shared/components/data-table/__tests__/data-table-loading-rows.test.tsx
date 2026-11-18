/**
 * Things must not move when a list's data arrives (acceptance review
 * 2026-11-18):
 * - the loading placeholder drew a fixed five rows whatever the list held, so
 *   a list of 25 grew by 20 rows and a list of 1 shrank by 4 on load. It now
 *   draws the last row count this list showed, else five (a full page of
 *   placeholders collapsing to one real row moves more than five), capped to
 *   the page size and the viewport;
 * - the frame width that decides the column widths was read after paint (a
 *   passive effect), so the first frame had other widths than the second. It
 *   is read before paint now, also without a ResizeObserver.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'
import { loadingRowCount, resetRowCounts } from '../loading-rows'

type Row = { id: string; name: string; owner: string }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', enableHiding: false },
  { accessorKey: 'owner', header: 'Owner', meta: { hideBelow: 800, label: 'Owner' } },
]
const rows = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ id: String(i), name: `n${i}`, owner: 'o' }))

const skeletonRows = (c: HTMLElement) => c.querySelectorAll('[data-loading-row]').length

beforeEach(() => {
  resetRowCounts()
  window.sessionStorage.clear()
  Object.defineProperty(window, 'innerHeight', { configurable: true, value: 900 })
})
afterEach(() => vi.unstubAllGlobals())

describe('loading placeholder rows', () => {
  it('draws five rows, not the page size, when the list was never shown', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[]}
        isLoading
        pageSize={25}
        mobileCards={false}
        caption="Things"
      />
    )
    expect(skeletonRows(container)).toBe(5)
  })

  it('draws the count the list showed last time', () => {
    const first = render(
      <DataTable
        columns={columns}
        data={rows(3)}
        pageSize={25}
        mobileCards={false}
        caption="Things"
      />
    )
    first.unmount()
    const { container } = render(
      <DataTable
        columns={columns}
        data={[]}
        isLoading
        pageSize={25}
        mobileCards={false}
        caption="Things"
      />
    )
    expect(skeletonRows(container)).toBe(3)
  })

  it('never draws more rows than fit in the viewport, and at least one', () => {
    expect(loadingRowCount(undefined, 100, 900, 40)).toBe(5)
    expect(loadingRowCount(undefined, 3, 900, 40)).toBe(3)
    expect(loadingRowCount(undefined, 25, 100, 40)).toBe(3)
    expect(loadingRowCount(0, 25, 900, 40)).toBe(1)
    expect(loadingRowCount(20, 25, 900, 40)).toBe(20)
    expect(loadingRowCount(60, 100, 900, 40)).toBe(23)
    expect(loadingRowCount(undefined, 25, 0, 40)).toBe(5)
  })
})

describe('frame width', () => {
  it('is read before paint, without waiting for a ResizeObserver', () => {
    vi.stubGlobal('ResizeObserver', undefined)
    const saved = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth')
    Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
      configurable: true,
      get(this: HTMLElement) {
        return this.dataset.density !== undefined ? 700 : 0
      },
    })
    try {
      render(<DataTable columns={columns} data={rows(1)} mobileCards={false} />)
      // A 700 px frame drops the Owner column (hideBelow 800) on the first render.
      expect(screen.getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Name'])
    } finally {
      if (saved) Object.defineProperty(HTMLElement.prototype, 'clientWidth', saved)
    }
  })
})
