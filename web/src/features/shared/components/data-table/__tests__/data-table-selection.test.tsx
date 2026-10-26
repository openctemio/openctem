import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { Checkbox } from '@/components/ui/checkbox'
import { DataTable } from '../data-table'

type Row = { id: string; name: string }
const columns: ColumnDef<Row>[] = [
  {
    id: 'select',
    header: () => null,
    cell: ({ row }) => (
      <Checkbox
        checked={row.getIsSelected()}
        onCheckedChange={(v) => row.toggleSelected(!!v)}
        aria-label={`pick ${row.original.name}`}
      />
    ),
  },
  { accessorKey: 'name', header: 'Name' },
]
const rows: Row[] = [
  { id: 'a', name: 'alpha' },
  { id: 'b', name: 'beta' },
]

type Extra = Partial<Parameters<typeof DataTable<Row, unknown>>[0]>
function table(extra: Extra = {}) {
  return (
    <DataTable<Row, unknown>
      columns={columns}
      data={rows}
      showSearch={false}
      getRowId={(r) => r.id}
      manualPagination
      rowCount={100}
      pagination={{ pageIndex: 0, pageSize: 20 }}
      onPaginationChange={() => {}}
      sorting={[]}
      onSortingChange={() => {}}
      {...extra}
    />
  )
}

const last = (fn: ReturnType<typeof vi.fn>) => fn.mock.calls.at(-1)?.[0] as Row[]

describe('DataTable selection scope', () => {
  afterEach(() => {
    Object.defineProperty(window, 'innerWidth', { value: 1024, configurable: true })
  })

  it('clears the selection when the page changes', () => {
    const onSelectionChange = vi.fn()
    const { rerender } = render(table({ onSelectionChange }))
    fireEvent.click(screen.getByLabelText('pick alpha'))
    expect(last(onSelectionChange).map((r) => r.id)).toEqual(['a'])
    rerender(table({ onSelectionChange, pagination: { pageIndex: 1, pageSize: 20 } }))
    expect(last(onSelectionChange)).toEqual([])
    expect(screen.getByLabelText('pick alpha')).not.toBeChecked()
  })

  it('clears the selection when the page size changes', () => {
    const onSelectionChange = vi.fn()
    const { rerender } = render(table({ onSelectionChange }))
    fireEvent.click(screen.getByLabelText('pick beta'))
    rerender(table({ onSelectionChange, pagination: { pageIndex: 0, pageSize: 50 } }))
    expect(last(onSelectionChange)).toEqual([])
  })

  it('clears the selection when the sort changes', () => {
    const onSelectionChange = vi.fn()
    const sorted: SortingState = [{ id: 'name', desc: true }]
    const { rerender } = render(table({ onSelectionChange }))
    fireEvent.click(screen.getByLabelText('pick alpha'))
    rerender(table({ onSelectionChange, sorting: sorted }))
    expect(last(onSelectionChange)).toEqual([])
  })

  it('clears the selection when the parent bumps resetSelectionKey (filter, search, view)', () => {
    const onSelectionChange = vi.fn()
    const { rerender } = render(table({ onSelectionChange, resetSelectionKey: 'f1' }))
    fireEvent.click(screen.getByLabelText('pick alpha'))
    rerender(table({ onSelectionChange, resetSelectionKey: 'f2' }))
    expect(last(onSelectionChange)).toEqual([])
  })

  it('keeps the selection when nothing about the page changed', () => {
    const onSelectionChange = vi.fn()
    const { rerender } = render(table({ onSelectionChange, resetSelectionKey: 'f1' }))
    fireEvent.click(screen.getByLabelText('pick alpha'))
    rerender(table({ onSelectionChange, resetSelectionKey: 'f1' }))
    expect(last(onSelectionChange).map((r) => r.id)).toEqual(['a'])
  })

  it('gives a phone card the row selection, and the card selects the same row', () => {
    Object.defineProperty(window, 'innerWidth', { value: 390, configurable: true })
    const onSelectionChange = vi.fn()
    const mobileRow = vi.fn((row: Row, sel) => (
      <label>
        <input
          type="checkbox"
          aria-label={`card ${row.name}`}
          checked={sel.selected}
          disabled={!sel.selectable}
          onChange={(e) => sel.onSelectedChange(e.target.checked)}
        />
        {row.name}
      </label>
    ))
    const { rerender } = render(table({ onSelectionChange, mobileRow }))
    fireEvent.click(screen.getByLabelText('card beta'))
    expect(last(onSelectionChange).map((r) => r.id)).toEqual(['b'])
    expect(screen.getByLabelText('card beta')).toBeChecked()
    rerender(table({ onSelectionChange, mobileRow, pagination: { pageIndex: 2, pageSize: 20 } }))
    expect(last(onSelectionChange)).toEqual([])
  })

  it('tells the card the table has no selection column', () => {
    Object.defineProperty(window, 'innerWidth', { value: 390, configurable: true })
    const seen: boolean[] = []
    render(
      table({
        columns: [columns[1]],
        mobileRow: (_r: Row, sel) => {
          seen.push(sel.selectable)
          return <span>row</span>
        },
      })
    )
    expect(seen.every((s) => s === false)).toBe(true)
    expect(seen.length).toBeGreaterThan(0)
  })
})
