import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table/data-table'

type Row = { id: string; name: string }
const columns: ColumnDef<Row>[] = [{ accessorKey: 'name', header: 'Name' }]

/** An empty list shows its empty state only: no "Showing 0 - 0 of 0", no "Page 1 of 0". */
describe('DataTable pagination on an empty list', () => {
  it('hides the footer when there is no row', () => {
    render(<DataTable columns={columns} data={[]} emptyMessage="No hosts yet" />)
    expect(screen.getByText('No hosts yet')).toBeInTheDocument()
    expect(screen.queryByText(/Showing 0/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Page 1 of/)).not.toBeInTheDocument()
  })

  it('hides it under server pagination with a zero count', () => {
    render(
      <DataTable
        columns={columns}
        data={[]}
        manualPagination
        rowCount={0}
        pageCount={0}
        emptyMessage="No hosts yet"
      />
    )
    expect(screen.queryByText(/of 0/)).not.toBeInTheDocument()
  })

  it('shows it, never "of 0", once there are rows', () => {
    render(<DataTable columns={columns} data={[{ id: '1', name: 'a' }]} />)
    expect(screen.getByText(/Showing 1 - 1 of 1/)).toBeInTheDocument()
    expect(screen.getByText('Page 1 of 1')).toBeInTheDocument()
  })
})

describe('DataTable name column', () => {
  it('keeps a minimum width on the pinned name column so other columns cannot squeeze it', () => {
    const cols: ColumnDef<Row>[] = [
      { accessorKey: 'name', header: 'Name' },
      { id: 'actions', cell: () => null },
    ]
    render(<DataTable columns={cols} data={[{ id: '1', name: 'a' }]} />)
    const th = screen.getByRole('columnheader', { name: 'Name' })
    expect(th.className).toContain('min-w-[min(12rem,36vw)]')
  })
})
