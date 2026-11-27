/**
 * The one pager: "Showing 26 to 50 of 418 findings", Rows per page 25 / 50 /
 * 100 whatever the page passes (plus a size a link asked for), "Page 2 of 17",
 * ghost arrows, and Last page disabled with its reason without a known total.
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

  it('a capped total disables Last page with its reason and shows no page count', () => {
    render(<DataTable {...server(1, 25, { rowCount: 10_000, rowCountCapped: true })} />)
    const last = screen.getByRole('button', { name: 'Last page' })
    expect(last).toBeDisabled()
    expect(last).toHaveAccessibleDescription('More match than were counted. Narrow the list.')
    expect(screen.getByText('Page 2')).toBeInTheDocument()
    expect(screen.getByText(/of 10,000\+ findings/)).toBeInTheDocument()
  })

  it('a known total has Last page without a reason', () => {
    render(<DataTable {...server(1, 25)} />)
    const last = screen.getByRole('button', { name: 'Last page' })
    expect(last).toBeEnabled()
    expect(last.parentElement).not.toHaveAttribute('title')
  })

  it('an unknown total shows the rows on screen, Page N, and Last page disabled with its reason', () => {
    render(<DataTable {...server(0, 25, { rowCount: undefined, countUnavailable: true })} />)
    expect(screen.getByText('Showing 1 to 25')).toBeInTheDocument()
    expect(screen.queryByText(/of .* findings/)).not.toBeInTheDocument()
    expect(screen.getByText('Page 1')).toBeInTheDocument()
    const last = screen.getByRole('button', { name: 'Last page' })
    expect(last).toBeDisabled()
    expect(last).toHaveAccessibleDescription('The total is not known yet')
    expect(last.parentElement).toHaveAttribute('title', 'The total is not known yet')
    expect(screen.getByRole('button', { name: 'Next page' })).toBeEnabled()
    // The title row says the count failed; the footer repeats it only for a
    // list that retries from the footer.
    expect(screen.queryByText('Could not count')).not.toBeInTheDocument()
  })

  it('an unknown total with a footer retry says so and retries', async () => {
    const onRetryCount = vi.fn()
    render(
      <DataTable
        {...server(0, 25, { rowCount: undefined, countUnavailable: true, onRetryCount })}
      />
    )
    expect(screen.getByText('Could not count')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetryCount).toHaveBeenCalledTimes(1)
  })

  it('a list that fits one page has no pager: no "Showing 1 to 4 of 4", no "Page 1 of 1"', () => {
    render(
      <DataTable columns={columns} data={rows(4)} getRowId={(r) => r.id} paginationNoun="rules" />
    )
    expect(screen.queryByText(/Showing 1 to 4/)).not.toBeInTheDocument()
    expect(screen.queryByText('Page 1 of 1')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument()
  })

  it('a list past the smallest page size keeps its pager on the one page it shows', () => {
    render(
      <DataTable
        columns={columns}
        data={rows(30)}
        getRowId={(r) => r.id}
        paginationNoun="rules"
        pageSize={50}
      />
    )
    expect(screen.getByText('Page 1 of 1')).toBeInTheDocument()
  })

  it('a table with no toolbar control offers Display in its pager, not on a row of its own', () => {
    render(<DataTable {...server(0, 25, { showSearch: false })} />)
    expect(screen.queryByTestId('data-table-toolbar')).not.toBeInTheDocument()
    const pager = document.querySelector('[data-slot="data-table-pager"]')!
    expect(pager.querySelector('[aria-label="Display: density and columns"]')).not.toBeNull()
  })
})
