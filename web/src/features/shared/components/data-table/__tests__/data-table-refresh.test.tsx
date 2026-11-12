import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { name: string }
const columns: ColumnDef<Row>[] = [{ accessorKey: 'name', header: 'Name' }]
const rows: Row[] = [{ name: 'alpha' }, { name: 'beta' }]

function renderTable(isRefreshing: boolean) {
  return render(
    <DataTable
      columns={columns}
      data={rows}
      showSearch={false}
      search={{ value: '', onChange: () => {}, placeholder: 'Search rows', label: 'Search rows' }}
      isRefreshing={isRefreshing}
      refreshingLabel="Refreshing rows"
    />
  )
}

describe('DataTable refresh bar', () => {
  it('is absent while not refreshing', () => {
    renderTable(false)
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
    expect(document.querySelector('[data-slot="table-refresh-bar"]')).toBeNull()
  })

  it('sits inside the table frame, after the toolbar and its search box, only while refreshing', () => {
    const { rerender } = renderTable(true)
    const search = screen.getByRole('searchbox', { name: 'Search rows' })
    const bars = screen.getAllByRole('progressbar', { name: 'Refreshing rows' })
    expect(bars.length).toBeGreaterThan(0)
    for (const bar of bars) {
      const frame = bar.parentElement as HTMLElement
      // The frame is the bordered, positioned box that holds the rows; the
      // bar is overlaid on its top edge, so the layout does not move.
      expect(frame.className).toMatch(/\brelative\b/)
      expect(frame.className).toMatch(/\bborder\b/)
      expect(bar.className).toBe('table-refresh-bar')
      expect(frame.contains(search)).toBe(false)
      // Never before the toolbar: the search box precedes the bar in the DOM.
      expect(search.compareDocumentPosition(bar) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
      // It is the frame's first child, ahead of the header row or cards.
      expect(frame.firstElementChild).toBe(bar)
    }
    const tableBar = bars.find((b) => b.parentElement?.querySelector('table'))
    expect(tableBar).toBeDefined()

    rerender(
      <DataTable
        columns={columns}
        data={rows}
        showSearch={false}
        search={{ value: '', onChange: () => {}, placeholder: 'Search rows', label: 'Search rows' }}
        isRefreshing={false}
      />
    )
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
  })

  it('falls back to the shared label', () => {
    render(<DataTable columns={columns} data={rows} isRefreshing />)
    expect(screen.getAllByRole('progressbar', { name: 'Refreshing' }).length).toBeGreaterThan(0)
  })
})
