/**
 * The pinned actions column (`pinActions`): as wide as its widest real
 * content and never wider than its declared width; with no action on any row
 * of the page it has no box at all, so it covers nothing and the page does
 * not scroll sideways for it.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string; pending: boolean }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', enableHiding: false },
  {
    id: 'actions',
    meta: { kind: 'actions', width: 196, label: 'Actions' },
    header: () => <span className="sr-only">Actions</span>,
    enableHiding: false,
    cell: ({ row }) =>
      row.original.pending ? (
        <div className="flex gap-2">
          <button type="button">Approve</button>
          <button type="button">Reject</button>
        </div>
      ) : null,
  },
]

const pinnedCells = (container: HTMLElement) =>
  Array.from(container.querySelectorAll<HTMLElement>('[data-pinned-actions]'))

describe('DataTable pinned actions column', () => {
  it('sizes to its widest real content, capped at the declared width', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[
          { id: '1', name: 'waiting', pending: true },
          { id: '2', name: 'decided', pending: false },
        ]}
        getRowId={(r) => r.id}
        pinActions
      />
    )
    const cells = pinnedCells(container)
    // The header and both rows.
    expect(cells).toHaveLength(3)
    for (const cell of cells) {
      // 1px in the automatic layout = the widest cell's one-line content.
      expect(cell.style.width).toBe('1px')
      expect(cell.style.maxWidth).toBe('196px')
      expect(cell.style.minWidth).toBe('')
      expect(cell).toHaveClass('sticky', 'whitespace-nowrap')
      expect(cell).not.toHaveClass('p-0')
    }
    expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument()
  })

  it('has no box while no row of the page has an action', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[
          { id: '1', name: 'decided', pending: false },
          { id: '2', name: 'cancelled', pending: false },
        ]}
        getRowId={(r) => r.id}
        pinActions
      />
    )
    for (const cell of pinnedCells(container)) {
      // jsdom writes a zero max-width without its unit.
      expect(parseFloat(cell.style.width)).toBe(0)
      expect(parseFloat(cell.style.maxWidth)).toBe(0)
      expect(cell).toHaveClass('p-0', 'border-0', 'overflow-hidden')
    }
    // The header keeps its name for assistive technology.
    expect(screen.getByRole('columnheader', { name: 'Actions' })).toBeInTheDocument()
  })

  it('comes back when a row with an action arrives', () => {
    const { container, rerender } = render(
      <DataTable
        columns={columns}
        data={[{ id: '1', name: 'decided', pending: false }]}
        getRowId={(r) => r.id}
        pinActions
      />
    )
    expect(pinnedCells(container)[0]).toHaveClass('p-0')
    rerender(
      <DataTable
        columns={columns}
        data={[
          { id: '1', name: 'decided', pending: false },
          { id: '3', name: 'new request', pending: true },
        ]}
        getRowId={(r) => r.id}
        pinActions
      />
    )
    for (const cell of pinnedCells(container)) {
      expect(cell.style.width).toBe('1px')
      expect(cell).not.toHaveClass('p-0')
    }
  })

  it('keeps the declared width when the column is not pinned', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ id: '2', name: 'decided', pending: false }]}
        getRowId={(r) => r.id}
      />
    )
    expect(pinnedCells(container)).toHaveLength(0)
    const th = screen.getByRole('columnheader', { name: 'Actions' })
    expect(th.style.width).toBe('196px')
  })
})
