import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { name: string }
const columns: ColumnDef<Row>[] = [{ accessorKey: 'name', header: 'Name' }]

describe('DataTable empty and error states', () => {
  it('an emptyState replaces the default empty block', () => {
    render(<DataTable columns={columns} data={[]} emptyState={<p>Nothing yet, import some</p>} />)
    expect(screen.getAllByText('Nothing yet, import some').length).toBeGreaterThan(0)
    expect(screen.queryByText('No results found')).not.toBeInTheDocument()
  })

  it('an errorState keeps the toolbar and hides the rows and the pager', () => {
    render(
      <DataTable
        columns={columns}
        data={[{ name: 'stale row' }]}
        toolbarStart={<input aria-label="my search" />}
        errorState={<p role="alert">could not load</p>}
      />
    )
    expect(screen.getByLabelText('my search')).toBeInTheDocument()
    expect(screen.getAllByRole('alert').length).toBeGreaterThan(0)
    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument()
  })
})
