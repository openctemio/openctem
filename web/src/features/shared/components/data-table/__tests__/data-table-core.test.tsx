/**
 * The table core: one-click sort with aria-sort only on the sorted header, a
 * live region, widths and alignment from the column kind, the accessible
 * name, the two kinds of empty list, partial counts, a stale read, and the
 * scroll mode chosen from the measurement.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { DataTable } from '../data-table'
import { DataTableColumnHeader } from '../data-table-column-header'
import { columnLayout } from '../column-meta'
import { PageHeader, PAGE_TITLE_ID } from '../../page-header'

type Row = { id: string; name: string; count: number; seen: string }
const columns: ColumnDef<Row>[] = [
  {
    accessorKey: 'name',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
    meta: { kind: 'name', label: 'Name' },
  },
  {
    accessorKey: 'count',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Count" />,
    meta: { kind: 'number', label: 'Count' },
  },
  {
    accessorKey: 'seen',
    header: 'Last seen',
    enableSorting: false,
    meta: { kind: 'datetime-recent', label: 'Last seen', width: 120 },
  },
]
const rows: Row[] = [
  { id: '1', name: 'beta', count: 2, seen: 'x' },
  { id: '2', name: 'alpha', count: 10, seen: 'y' },
]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1440 })
  window.localStorage.clear()
})
afterEach(() => vi.restoreAllMocks())

const header = (name: string) =>
  screen.getAllByRole('columnheader').find((h) => h.textContent?.includes(name)) as HTMLElement
const names = () =>
  screen
    .getAllByRole('row')
    .slice(1)
    .map((r) => within(r).getAllByRole('cell')[0].textContent)

function ServerSorted({ onSort }: { onSort?: (s: SortingState) => void }) {
  const [sorting, setSorting] = useState<SortingState>([{ id: 'count', desc: true }])
  return (
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(r) => r.id}
      manualPagination
      rowCount={2}
      pagination={{ pageIndex: 0, pageSize: 25 }}
      onPaginationChange={() => {}}
      sorting={sorting}
      onSortingChange={(s) => {
        setSorting(s)
        onSort?.(s)
      }}
    />
  )
}

describe('sorting', () => {
  it('one click sorts by the column in its natural first direction, the next turns it', async () => {
    const onSort = vi.fn()
    render(<ServerSorted onSort={onSort} />)
    // Text sorts ascending first.
    await userEvent.click(within(header('Name')).getByRole('button', { name: 'Name' }))
    expect(onSort).toHaveBeenLastCalledWith([{ id: 'name', desc: false }])
    await userEvent.click(within(header('Name')).getByRole('button', { name: 'Name' }))
    expect(onSort).toHaveBeenLastCalledWith([{ id: 'name', desc: true }])
    // No menu opened on the way.
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('numbers sort descending first', async () => {
    const onSort = vi.fn()
    render(<ServerSorted onSort={onSort} />)
    await userEvent.click(within(header('Name')).getByRole('button', { name: 'Name' }))
    await userEvent.click(within(header('Count')).getByRole('button', { name: 'Count' }))
    expect(onSort).toHaveBeenLastCalledWith([{ id: 'count', desc: true }])
  })

  it('aria-sort is only on the sorted header, and the arrow only shows there', async () => {
    render(<ServerSorted />)
    expect(header('Count')).toHaveAttribute('aria-sort', 'descending')
    expect(header('Name')).not.toHaveAttribute('aria-sort')
    expect(header('Last seen')).not.toHaveAttribute('aria-sort')
    await userEvent.click(within(header('Name')).getByRole('button', { name: 'Name' }))
    expect(header('Name')).toHaveAttribute('aria-sort', 'ascending')
    expect(header('Count')).not.toHaveAttribute('aria-sort')
  })

  it('announces the new sort in the live region', async () => {
    render(<ServerSorted />)
    const region = screen.getByRole('status')
    expect(region).toHaveTextContent('')
    await userEvent.click(within(header('Name')).getByRole('button', { name: 'Name' }))
    expect(region).toHaveTextContent('Sorted by Name, ascending')
  })

  it('sorts the rows of a client-side table on one click', async () => {
    render(<DataTable columns={columns} data={rows} />)
    await userEvent.click(within(header('Name')).getByRole('button', { name: 'Name' }))
    expect(names()).toEqual(['alpha', 'beta'])
  })

  it('an empty list has no sort buttons', () => {
    render(<DataTable columns={columns} data={[]} />)
    expect(within(header('Name')).queryByRole('button')).not.toBeInTheDocument()
  })
})

describe('column kinds', () => {
  it('a number column is end-aligned; widths come from the kind and the column meta', () => {
    render(<DataTable columns={columns} data={rows} />)
    expect(header('Count')).toHaveClass('text-end')
    const seen = header('Last seen')
    expect(seen).toHaveClass('text-end')
    expect(seen.style.width).toBe('120px')
    expect(seen.style.minWidth).toBe('120px')
    expect(seen.style.maxWidth).toBe('120px')
    const cell = screen.getByText('x').closest('td') as HTMLElement
    expect(cell.style.width).toBe('120px')
  })

  it('layout defaults: select 40, actions 48, flexible asset range, explicit width wins', () => {
    expect(columnLayout('select', undefined).style).toEqual({
      width: 40,
      minWidth: 40,
      maxWidth: 40,
    })
    expect(columnLayout('actions', undefined).style?.width).toBe(48)
    expect(columnLayout('a', { kind: 'asset', minWidth: 112, maxWidth: 160 }).style).toEqual({
      minWidth: 112,
      maxWidth: 160,
    })
    expect(columnLayout('t', undefined)).toMatchObject({ kind: 'text', style: undefined })
    expect(columnLayout('d', { kind: 'date' }).sortFirst).toBe('desc')
  })
})

describe('accessible name', () => {
  it('a caption names the table', () => {
    render(<DataTable columns={columns} data={rows} caption="Open findings" />)
    expect(screen.getByRole('table', { name: 'Open findings' })).toBeInTheDocument()
  })

  it('without a caption the page title names it', () => {
    render(
      <>
        <PageHeader title="Findings" />
        <DataTable columns={columns} data={rows} />
      </>
    )
    expect(screen.getByRole('heading', { level: 1 })).toHaveAttribute('id', PAGE_TITLE_ID)
    expect(screen.getByRole('table', { name: 'Findings' })).toBeInTheDocument()
  })
})

describe('empty kinds', () => {
  const kinds = { nothingYet: <p>No findings yet</p> }

  it('nothing yet when no filter is applied', () => {
    render(<DataTable columns={columns} data={[]} emptyState={kinds} />)
    expect(screen.getByText('No findings yet')).toBeInTheDocument()
  })

  it('no match with Clear filters when a filter is applied', async () => {
    const clear = vi.fn()
    render(
      <DataTable columns={columns} data={[]} emptyState={kinds} isFiltered onClearFilters={clear} />
    )
    expect(screen.queryByText('No findings yet')).not.toBeInTheDocument()
    expect(screen.getByText('No results found')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(clear).toHaveBeenCalled()
  })
})

describe('footer states', () => {
  const paged = {
    columns,
    data: rows,
    getRowId: (r: Row) => r.id,
    manualPagination: true,
    pagination: { pageIndex: 0, pageSize: 2 },
    onPaginationChange: () => {},
  }

  it('partial counts: no total, Could not count with Retry, no Last page', async () => {
    const retry = vi.fn()
    render(<DataTable {...paged} countUnavailable onRetryCount={retry} />)
    expect(screen.getByText('Showing 1 - 2')).toBeInTheDocument()
    expect(screen.getByText('Page 1')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Last page' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Next page' })).toBeEnabled()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(retry).toHaveBeenCalled()
  })

  it('a stale read says when it was updated and offers a refresh', async () => {
    const refresh = vi.fn()
    render(
      <DataTable
        {...paged}
        rowCount={2}
        staleAt={new Date(Date.now() - 12 * 60_000)}
        onRefresh={refresh}
      />
    )
    expect(screen.getByText(/Updated/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Refresh now' }))
    expect(refresh).toHaveBeenCalled()
  })

  it('announces the result count when a refresh ends', () => {
    const { rerender } = render(<DataTable {...paged} rowCount={2} isRefreshing />)
    rerender(<DataTable {...paged} rowCount={2} isRefreshing={false} />)
    expect(screen.getByRole('status')).toHaveTextContent('2 results')
  })
})

describe('scroll mode', () => {
  it('without stickyHeader the frame scrolls as before and the header does not stick', () => {
    render(<DataTable columns={columns} data={rows} />)
    expect(screen.getByRole('region', { name: 'Table, scrollable' })).toBeInTheDocument()
    expect(header('Count')).not.toHaveClass('sticky')
    expect(header('Name')).not.toHaveClass('top-0')
  })

  it('stickyHeader: fits: clip, no scroll region; wider than the frame: the frame scrolls as a region', () => {
    let tableWidth = 800
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockImplementation(function (
      this: HTMLElement
    ) {
      return this.tagName === 'TABLE' ? tableWidth : 0
    })
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(function (
      this: HTMLElement
    ) {
      return this.dataset.slot === 'table-container' ? 1000 : 0
    })
    const { container, rerender } = render(<DataTable columns={columns} data={rows} stickyHeader />)
    const frame = () => container.querySelector('[data-scroll-mode]') as HTMLElement
    expect(frame()).toHaveAttribute('data-scroll-mode', 'clip')
    expect(screen.queryByRole('region')).not.toBeInTheDocument()
    tableWidth = 1400
    act(() => {
      rerender(<DataTable columns={columns} data={[...rows]} stickyHeader />)
    })
    expect(frame()).toHaveAttribute('data-scroll-mode', 'scroll')
    expect(screen.getByRole('region', { name: 'Table, scrollable' })).toBeInTheDocument()
    // The header sticks to the top of whichever element scrolls.
    expect(header('Name')).toHaveClass('sticky', 'top-0')
  })
})
