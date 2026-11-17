/**
 * A list drawn as cards (below 768px) has no numbered pager: its footer is
 * "Show 25 more" and "50 of 418". The button grows the page size by one step
 * up to the largest size the API returns.
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

const setWidth = (value: number) =>
  Object.defineProperty(window, 'innerWidth', { configurable: true, value })

beforeEach(() => {
  setWidth(390)
  window.localStorage.clear()
})
afterEach(() => {
  setWidth(1440)
  vi.restoreAllMocks()
})

const server = (pageSize: number, extra: Record<string, unknown> = {}) => ({
  columns,
  data: rows(pageSize),
  getRowId: (r: Row) => r.id,
  manualPagination: true,
  rowCount: 418,
  paginationNoun: 'findings',
  pagination: { pageIndex: 0, pageSize },
  onPaginationChange: vi.fn(),
  ...extra,
})

const more = () => screen.queryByRole('button', { name: /^Show .* more$/ })

describe('phone footer of a card list', () => {
  it('replaces the pager with "Show 25 more" and "25 of 418"', () => {
    const { container } = render(<DataTable {...server(25)} />)
    expect(container.querySelector('[data-slot="data-table-pager"]')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument()
    const button = screen.getByRole('button', { name: 'Show 25 more' })
    expect(button).toHaveAttribute('data-slot', 'phone-show-more')
    expect(button).toHaveClass('w-full')
    expect(button.className).toMatch(/(^|\s)border(\s|$)/)
    expect(container.querySelector('[data-slot="phone-shown-count"]')).toHaveTextContent(
      '25 of 418'
    )
  })

  it('asks the page for the next size, on the first page', async () => {
    const props = server(50)
    render(<DataTable {...props} />)
    await userEvent.click(screen.getByRole('button', { name: 'Show 25 more' }))
    expect(props.onPaginationChange).toHaveBeenCalledWith({ pageIndex: 0, pageSize: 75 })
  })

  it('moves a size between two steps to the next step', async () => {
    const props = server(20, { pageSizeOptions: [10, 20, 30] })
    render(<DataTable {...props} />)
    await userEvent.click(screen.getByRole('button', { name: 'Show 5 more' }))
    expect(props.onPaginationChange).toHaveBeenCalledWith({ pageIndex: 0, pageSize: 25 })
  })

  it('names what is left when it is less than a step', () => {
    render(<DataTable {...server(50, { rowCount: 60 })} />)
    expect(screen.getByRole('button', { name: 'Show 10 more' })).toBeInTheDocument()
    expect(screen.getByText('50 of 60')).toBeInTheDocument()
  })

  it('has no button when everything is shown', () => {
    render(
      <DataTable {...server(18, { rowCount: 18, pagination: { pageIndex: 0, pageSize: 25 } })} />
    )
    expect(more()).not.toBeInTheDocument()
    expect(screen.getByText('18 of 18')).toBeInTheDocument()
  })

  it('stops at the largest page size and says how to see the rest', () => {
    const { container } = render(<DataTable {...server(100)} />)
    expect(more()).not.toBeInTheDocument()
    expect(screen.getByText('100 of 418')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="phone-more-cap"]')).toHaveTextContent(
      'These are the first 100. Narrow the filters to see the rest.'
    )
  })

  it('a capped or failed count reads "25 shown" and still offers more', () => {
    const { unmount } = render(
      <DataTable {...server(25, { rowCount: 10_000, rowCountCapped: true })} />
    )
    expect(screen.getByText('25 shown')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Show 25 more' })).toBeInTheDocument()
    unmount()
    render(<DataTable {...server(25, { rowCount: undefined, countUnavailable: true })} />)
    expect(screen.getByText('25 shown')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Show 25 more' })).toBeInTheDocument()
  })

  it('without a count, a short page is the end', () => {
    render(
      <DataTable
        {...server(12, {
          rowCount: undefined,
          countUnavailable: true,
          pagination: { pageIndex: 0, pageSize: 25 },
        })}
      />
    )
    expect(more()).not.toBeInTheDocument()
    expect(screen.getByText('12 shown')).toBeInTheDocument()
  })

  it('opens a link to a later page on the first one', () => {
    const props = server(25, { pagination: { pageIndex: 2, pageSize: 25 } })
    render(<DataTable {...props} />)
    expect(props.onPaginationChange).toHaveBeenCalledWith({ pageIndex: 0, pageSize: 25 })
  })

  it('waits for a running read', () => {
    render(<DataTable {...server(25, { isRefreshing: true })} />)
    expect(screen.getByRole('button', { name: 'Show 25 more' })).toBeDisabled()
  })

  it('focuses the first new card when the rows arrive', async () => {
    const props = server(25)
    const { container, rerender } = render(<DataTable {...props} />)
    await userEvent.click(screen.getByRole('button', { name: 'Show 25 more' }))
    rerender(<DataTable {...props} data={rows(50)} pagination={{ pageIndex: 0, pageSize: 50 }} />)
    const cards = container.querySelectorAll('[data-phone-card]')
    expect(cards).toHaveLength(50)
    expect(document.activeElement).toBe(cards[25])
    expect(cards[25]).toHaveAttribute('tabindex', '-1')
  })

  it('a list paged in the browser grows the same way, with no cap', async () => {
    render(<DataTable columns={columns} data={rows(130)} getRowId={(r) => r.id} />)
    expect(screen.getByText('25 of 130')).toBeInTheDocument()
    for (const shown of [50, 75, 100, 125]) {
      await userEvent.click(screen.getByRole('button', { name: 'Show 25 more' }))
      expect(screen.getByText(`${shown} of 130`)).toBeInTheDocument()
    }
    await userEvent.click(screen.getByRole('button', { name: 'Show 5 more' }))
    expect(screen.getByText('130 of 130')).toBeInTheDocument()
    expect(more()).not.toBeInTheDocument()
  })

  it('a list with one fixed size keeps the pager', () => {
    const { container } = render(<DataTable {...server(50, { pageSizeOptions: [50] })} />)
    expect(container.querySelector('[data-slot="data-table-pager"]')).not.toBeNull()
    expect(more()).not.toBeInTheDocument()
  })

  it('a desktop keeps the pager', () => {
    setWidth(1440)
    const { container } = render(<DataTable {...server(25)} />)
    expect(container.querySelector('[data-slot="data-table-pager"]')).not.toBeNull()
    expect(container.querySelector('[data-slot="phone-more-footer"]')).toBeNull()
  })

  it('a custom card is a focus target too', () => {
    const { container } = render(
      <DataTable {...server(3, { rowCount: 3 })} mobileRow={(r: Row) => <p>{r.name}</p>} />
    )
    expect(container.querySelectorAll('[data-phone-card][tabindex="-1"]')).toHaveLength(3)
  })
})
