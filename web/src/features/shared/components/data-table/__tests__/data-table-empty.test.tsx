import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { name: string }
const columns: ColumnDef<Row>[] = [{ accessorKey: 'name', header: 'Name' }]

describe('DataTable empty state', () => {
  it('an empty list without a search or filter does not ask to adjust one', () => {
    render(<DataTable columns={columns} data={[]} emptyMessage="No shared sensor is enrolled" />)
    expect(screen.getAllByText('No shared sensor is enrolled').length).toBeGreaterThan(0)
    expect(screen.queryByText(/Try adjusting your search/)).not.toBeInTheDocument()
  })

  it('a description the caller gives is always shown', () => {
    render(<DataTable columns={columns} data={[]} emptyDescription="Enroll one below." />)
    expect(screen.getAllByText('Enroll one below.').length).toBeGreaterThan(0)
  })
})
