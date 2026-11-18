import { afterEach, describe, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { act, render, screen } from '@testing-library/react'
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

describe('DataTable beforeRows', () => {
  it('draws page content after the toolbar and its chips row, before the rows', () => {
    render(
      <DataTable
        columns={columns}
        data={[{ name: 'a row' }]}
        toolbarStart={<input aria-label="my search" />}
        toolbarBelow={<span>chip</span>}
        beforeRows={<section aria-label="summary">summary block</section>}
      />
    )
    const chip = screen.getByText('chip')
    const block = screen.getByLabelText('summary')
    const row = screen.getAllByText('a row')[0]
    // Document order: chips row, then the block, then the rows.
    expect(chip.compareDocumentPosition(block) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(block.compareDocumentPosition(row) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('takes no box (and no gap of the frame) while the block renders nothing', () => {
    function NoBenchmarks() {
      return null
    }
    const { container } = render(
      <DataTable columns={columns} data={[{ name: 'a row' }]} beforeRows={<NoBenchmarks />} />
    )
    const slot = container.querySelector('[data-slot="table-before-rows"]')!
    expect(slot).toBeEmptyDOMElement()
    // The frame is `flex flex-col gap-4`: an empty child with a box would
    // still take a 16px gap. `empty:hidden` gives it display: none.
    expect(slot.parentElement!.className).toContain('gap-4')
    expect(slot.className.split(/\s+/)).toContain('empty:hidden')
  })

  it('reserves nothing without it', () => {
    const { container } = render(<DataTable columns={columns} data={[]} />)
    expect(container.querySelector('[data-slot="table-before-rows"]')).toBeNull()
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
    expect(screen.getByText("Couldn't load things")).toBeInTheDocument()
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

describe('DataTable stale read', () => {
  afterEach(() => vi.useRealTimers())
  const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000)

  it('a fresh read says nothing', () => {
    const { container } = render(
      <DataTable columns={columns} data={[{ name: 'row' }]} staleAt={minutesAgo(1)} />
    )
    expect(container.querySelector('[data-slot=table-stale]')).toBeNull()
  })

  it('a read older than 5 minutes says how old it is in the pager, with a refresh', async () => {
    const onRefresh = vi.fn()
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ name: 'row' }]}
        staleAt={minutesAgo(12)}
        onRefresh={onRefresh}
      />
    )
    const note = container.querySelector('[data-slot=table-stale]')
    expect(note).toHaveTextContent('Updated 12 minutes ago')
    expect(note?.closest('[data-slot=data-table-pager]')).not.toBeNull()
    const refresh = screen.getByRole('button', { name: 'Refresh now' })
    // The kit's icon size: 32, 36 on a phone.
    expect(refresh.className).toContain('size-control')
    await userEvent.click(refresh)
    expect(onRefresh).toHaveBeenCalledTimes(1)
    // The rows stay.
    expect(screen.getByText('row')).toBeInTheDocument()
  })

  it('a failed refresh says so at once, whatever the age', () => {
    const { container } = render(
      <DataTable columns={columns} data={[{ name: 'row' }]} staleAt={minutesAgo(0)} refreshFailed />
    )
    expect(container.querySelector('[data-slot=table-stale]')).not.toBeNull()
    expect(screen.getByText('row')).toBeInTheDocument()
  })

  it('the note appears as time passes, without new props', () => {
    vi.useFakeTimers()
    const { container } = render(
      <DataTable columns={columns} data={[{ name: 'row' }]} staleAt={new Date()} />
    )
    expect(container.querySelector('[data-slot=table-stale]')).toBeNull()
    act(() => {
      vi.advanceTimersByTime(6 * 60_000)
    })
    expect(container.querySelector('[data-slot=table-stale]')).not.toBeNull()
  })
})

describe('DataTable without a toolbar or rows', () => {
  it('showToolbar={false} draws no toolbar row', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[]}
        showToolbar={false}
        toolbarStart={<input aria-label="my search" />}
        emptyState={<p>Nothing yet</p>}
      />
    )
    expect(screen.queryByLabelText('my search')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /display/i })).not.toBeInTheDocument()
    expect(container.querySelector('[data-slot=list-toolbar]')).toBeNull()
    expect(screen.getAllByText('Nothing yet').length).toBeGreaterThan(0)
  })

  it('an empty list draws no header, so no select-all; it comes with the rows', () => {
    const bulk = { actions: null, rowLabel: (r: Row) => r.name }
    const sortable: ColumnDef<Row>[] = [
      { accessorKey: 'name', header: 'Name', enableSorting: true },
    ]
    const { rerender } = render(<DataTable columns={sortable} data={[]} bulk={bulk} />)
    expect(screen.queryByRole('checkbox', { name: 'Select all rows on this page' })).toBeNull()
    rerender(<DataTable columns={sortable} data={[{ name: 'row' }]} bulk={bulk} />)
    expect(screen.getByRole('checkbox', { name: 'Select all rows on this page' })).toBeEnabled()
  })
})
