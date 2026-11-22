/**
 * A cell that can be too wide for its column (a due date with a mark, a task
 * count) ends in an ellipsis, never a hard clip.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string; due: string; owner: string }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
  { accessorKey: 'due', header: 'Due', meta: { kind: 'due', label: 'Due' } },
  {
    accessorKey: 'owner',
    header: 'Owner',
    meta: { kind: 'owner', label: 'Owner', hideBelow: 5000 },
  },
]
const rows: Row[] = [{ id: '1', name: 'alpha', due: 'Apr 29, 2026, 23 d overdue', owner: 'Sam' }]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function renderTable() {
  return render(
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(r) => r.id}
      pagination={{ pageIndex: 0, pageSize: 25 }}
      onPaginationChange={() => {}}
    />
  )
}

describe('DataTable cut cells', () => {
  it('ends a fixed-width cell in an ellipsis instead of clipping it', () => {
    renderTable()
    const cell = screen.getAllByText('Apr 29, 2026, 23 d overdue')[0].closest('td')!
    expect(cell.className).toContain('overflow-hidden')
    expect(cell.className).toContain('text-ellipsis')
  })

  it('does not put the ellipsis on the name cell, which truncates its own link', () => {
    renderTable()
    const cell = screen.getAllByText('alpha')[0].closest('td')!
    expect(cell.className).not.toContain('text-ellipsis')
  })
})
