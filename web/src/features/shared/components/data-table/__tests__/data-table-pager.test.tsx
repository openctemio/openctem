/**
 * The one pager: "Showing 26 to 50 of 418 findings", Rows per page 25 / 50 /
 * 100 whatever the page passes (plus a size a link asked for), "Page 2 of 17",
 * ghost arrows, and no Last page without a known total.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
]
const rows = (n: number): Row[] =>
  Array.from({ length: n }, (_, i) => ({ id: `${i}`, name: `r${i}` }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// Radix Select measures and scrolls; jsdom has neither.
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false

beforeEach(() => {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1440 })
  window.localStorage.clear()
})
afterEach(() => vi.restoreAllMocks())

const server = (pageIndex: number, pageSize: number, extra = {}) => ({
  columns,
  data: rows(pageSize),
  getRowId: (r: Row) => r.id,
  manualPagination: true,
  rowCount: 418,
  paginationNoun: 'findings',
  pagination: { pageIndex, pageSize },
  onPaginationChange: () => {},
  ...extra,
})

describe('pager', () => {
  it('says where the page is, 12/16, with ghost arrows', () => {
    render(<DataTable {...server(1, 25)} />)
    const showing = screen.getByText('Showing 26 to 50 of 418 findings')
    expect(showing.parentElement).toHaveClass('text-cap')
    expect(screen.getByText('Page 2 of 17')).toHaveClass('text-cap')
    for (const name of ['First page', 'Previous page', 'Next page', 'Last page']) {
      // Ghost: navigation in a quiet footer has no border.
      expect(screen.getByRole('button', { name }).className).not.toMatch(/(^|\s)border(\s|$)/)
    }
  })

  it('a client list starts at 25 rows', () => {
    render(<DataTable columns={columns} data={rows(60)} getRowId={(r) => r.id} />)
    expect(screen.getByText(/Showing 1 to 25 of 60/)).toBeInTheDocument()
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
  })

  it('offers 25, 50 and 100 whatever the page passes, plus a size a link asked for', async () => {
    render(<DataTable {...server(0, 20, { pageSizeOptions: [10, 20, 30] })} />)
    await userEvent.click(screen.getByRole('combobox', { name: /rows per page/i }))
    const options = screen.getAllByRole('option').map((o) => o.textContent)
    expect(options).toEqual(['20', '25', '50', '100'])
  })

  it('a list with one fixed size has no choice', () => {
    render(<DataTable {...server(0, 50, { pageSizeOptions: [50] })} />)
    expect(screen.queryByRole('combobox', { name: /rows per page/i })).not.toBeInTheDocument()
  })

  it('a capped total has no Last page and no page count', () => {
    render(<DataTable {...server(1, 25, { rowCount: 10_000, rowCountCapped: true })} />)
    expect(screen.queryByRole('button', { name: 'Last page' })).not.toBeInTheDocument()
    expect(screen.getByText('Page 2')).toBeInTheDocument()
    expect(screen.getByText(/of 10,000\+ findings/)).toBeInTheDocument()
  })
})
