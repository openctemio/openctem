/**
 * Selection and bulk: the checkbox column only with `bulk`, the header
 * checkbox mixed on a partial page, Shift-click and `x` / Shift+x ranges, the
 * bulk bar (count, two actions, More, X, Esc), "Select all N that match" as a
 * filter selection (and its limit), the live region, and row menus waiting
 * while rows are selected.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'
import type { DataTableBulk, DataTableSelection } from '../data-table-selection'
import { DropdownMenuItem } from '@/components/ui/dropdown-menu'

type Row = { id: string; name: string }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
  {
    id: 'actions',
    header: () => null,
    cell: ({ row }) => <button type="button">Menu {row.original.name}</button>,
    meta: { kind: 'actions', label: 'Actions' },
  },
]
const rows: Row[] = ['a', 'b', 'c', 'd', 'e'].map((n, i) => ({ id: String(i + 1), name: n }))

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

function setup(bulk: Partial<DataTableBulk<Row>> = {}, extra: { rowCount?: number } = {}) {
  const onSelectionChange = vi.fn<(s: DataTableSelection<Row> | null) => void>()
  const full: DataTableBulk<Row> = {
    rowLabel: (r) => r.name,
    actions: <button type="button">Assign to</button>,
    more: <DropdownMenuItem>Add to remediation</DropdownMenuItem>,
    onSelectionChange,
    ...bulk,
  }
  render(
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(r) => r.id}
      bulk={full}
      {...(extra.rowCount
        ? {
            manualPagination: true,
            rowCount: extra.rowCount,
            pagination: { pageIndex: 0, pageSize: 5 },
            onPaginationChange: () => {},
          }
        : {})}
    />
  )
  return { onSelectionChange }
}

const box = (name: string) => screen.getByRole('checkbox', { name: `Select ${name}` })
const bar = () => screen.queryByRole('toolbar', { name: /actions for selected rows/i })
const announcer = () => document.querySelector('[data-slot="table-announcer"]') as HTMLElement

describe('checkbox column', () => {
  it('is absent without bulk (no bulk permission, no checkboxes)', () => {
    render(<DataTable columns={columns} data={rows} getRowId={(r) => r.id} />)
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('comes first with bulk and replaces a page’s own select column', () => {
    const own: ColumnDef<Row>[] = [
      { id: 'select', header: 'own', cell: () => <span>own box</span> },
      ...columns,
    ]
    render(
      <DataTable
        columns={own}
        data={rows}
        getRowId={(r) => r.id}
        bulk={{ rowLabel: (r) => r.name, actions: null }}
      />
    )
    expect(screen.queryByText('own box')).not.toBeInTheDocument()
    const first = within(screen.getAllByRole('row')[1]).getAllByRole('cell')[0]
    expect(within(first).getByRole('checkbox')).toHaveAccessibleName('Select a')
  })

  it('takes the page’s own checkbox label when it gives one', () => {
    setup({ checkboxLabel: (r) => `Select finding ${r.name}` })
    expect(screen.getByRole('checkbox', { name: 'Select finding a' })).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: 'Select a' })).toBeNull()
  })

  it('header checkbox is mixed with some rows checked, checked with all', async () => {
    setup()
    const all = screen.getByRole('checkbox', { name: 'Select all rows on this page' })
    await userEvent.click(box('b'))
    expect(all).toHaveAttribute('aria-checked', 'mixed')
    await userEvent.click(all)
    expect(all).toHaveAttribute('aria-checked', 'true')
    expect(screen.getAllByRole('row')[1]).toHaveAttribute('data-state', 'selected')
  })
})

describe('ranges', () => {
  it('Shift-click selects from the last toggled row', async () => {
    const { onSelectionChange } = setup()
    await userEvent.click(box('b'))
    const user = userEvent.setup()
    await user.keyboard('{Shift>}')
    await user.click(box('d'))
    await user.keyboard('{/Shift}')
    const last = onSelectionChange.mock.calls.at(-1)?.[0]
    expect(last?.kind === 'ids' && last.rows.map((r) => r.name)).toEqual(['b', 'c', 'd'])
  })

  it('x toggles the focused row and Shift+x selects a range', async () => {
    const { onSelectionChange } = setup()
    const menuA = screen.getByRole('button', { name: 'Menu a' })
    fireEvent.keyDown(menuA, { key: 'x' })
    expect(box('a')).toHaveAttribute('aria-checked', 'true')
    fireEvent.keyDown(screen.getByRole('button', { name: 'Menu c' }), { key: 'X', shiftKey: true })
    const last = onSelectionChange.mock.calls.at(-1)?.[0]
    expect(last?.kind === 'ids' && last.rows.map((r) => r.name)).toEqual(['a', 'b', 'c'])
  })
})

describe('bulk bar', () => {
  it('shows count, actions, More and X; Esc clears; the live region says so', async () => {
    setup({ noun: 'findings selected' })
    expect(bar()).not.toBeInTheDocument()
    await userEvent.click(box('a'))
    await userEvent.click(box('b'))
    // The page's noun from sm up, the short word on a phone.
    expect(bar()).toHaveTextContent(/^2 findings selected/)
    expect(within(bar()!).getByText('selected')).toHaveClass('sm:hidden')
    expect(within(bar()!).getByRole('button', { name: 'Assign to' })).toBeInTheDocument()
    expect(within(bar()!).getByRole('button', { name: 'More actions' })).toBeInTheDocument()
    expect(announcer()).toHaveTextContent('2 selected')
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(bar()).not.toBeInTheDocument()
    expect(announcer()).toHaveTextContent('Selection cleared')
  })

  it('row menus wait while rows are selected', async () => {
    setup()
    const cell = screen.getByRole('button', { name: 'Menu a' }).closest('td')!
    expect(cell).not.toHaveAttribute('inert')
    await userEvent.click(box('c'))
    expect(cell).toHaveAttribute('inert')
  })
})

describe('select all that match', () => {
  it('is offered once the page is checked and turns the selection into the filter', async () => {
    const { onSelectionChange } = setup(
      { matching: { total: 418, max: 10_000 } },
      { rowCount: 418 }
    )
    await userEvent.click(box('a'))
    expect(screen.queryByRole('button', { name: /select all 418/i })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select all rows on this page' }))
    await userEvent.click(screen.getByRole('button', { name: 'Select all 418 that match' }))
    expect(onSelectionChange.mock.calls.at(-1)?.[0]).toEqual({ kind: 'filter', total: 418 })
    expect(within(bar()!).getByText('All 418 that match are selected')).toBeInTheDocument()
    expect(announcer()).toHaveTextContent('All 418 that match are selected')
    // Unchecking a row goes back to the checked rows.
    await userEvent.click(box('e'))
    expect(onSelectionChange.mock.calls.at(-1)?.[0]?.kind).toBe('ids')
  })

  it('above the server limit says why instead of offering it', async () => {
    setup({ matching: { total: 20_000, max: 10_000 } }, { rowCount: 20_000 })
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select all rows on this page' }))
    expect(screen.queryByRole('button', { name: /select all 20/i })).not.toBeInTheDocument()
    expect(screen.getByText(/Up to 10,000 at once/)).toBeInTheDocument()
  })
})
