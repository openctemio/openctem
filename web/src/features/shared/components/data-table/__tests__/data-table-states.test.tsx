import { describe, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
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

describe('DataTable error prop', () => {
  it('error with no rows shows the shared error state, Retry calls onRetry, the toolbar stays', async () => {
    const onRetry = vi.fn()
    render(
      <DataTable
        columns={columns}
        data={[]}
        toolbarStart={<input aria-label="my search" />}
        error={new Error('boom')}
        onRetry={onRetry}
        errorTitle="things"
      />
    )
    expect(screen.getAllByRole('alert').length).toBeGreaterThan(0)
    expect(screen.getByText('Failed to load things')).toBeInTheDocument()
    expect(screen.getByLabelText('my search')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('error with rows already loaded keeps the rows and shows no alert', () => {
    render(<DataTable columns={columns} data={[{ name: 'kept row' }]} error={new Error('boom')} />)
    expect(screen.getByText('kept row')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
