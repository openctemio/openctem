import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ColumnDef } from '@tanstack/react-table'

import { DataTable } from '../data-table/data-table'
import { TABLE_DENSITY_STORAGE_KEY } from '../data-table/use-table-density'

// Table density (style contract D14): compact (32px) or comfortable (40px),
// switched from every table's View menu, one per-user preference that every
// table follows; a table's own default applies until the user chooses.

type Row = { id: string; name: string }
const columns: ColumnDef<Row>[] = [{ accessorKey: 'name', header: 'Name' }]
const data: Row[] = [{ id: '1', name: 'edge-1' }]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function frame(container: HTMLElement) {
  return container.querySelector('[data-density]') as HTMLElement
}

describe('DataTable density', () => {
  const originalWidth = window.innerWidth
  beforeEach(() => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1440 })
    window.localStorage.clear()
  })
  afterEach(() => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: originalWidth })
    vi.restoreAllMocks()
  })

  it('uses the table default until the user chooses', () => {
    const { container } = render(
      <DataTable columns={columns} data={data} defaultDensity="compact" />
    )
    expect(frame(container)).toHaveAttribute('data-density', 'compact')
    expect(within(frame(container)).getByText('edge-1').closest('td')).toHaveClass('py-1')
  })

  it('is comfortable by default, so existing tables look the same', () => {
    const { container } = render(<DataTable columns={columns} data={data} />)
    expect(frame(container)).toHaveAttribute('data-density', 'comfortable')
    expect(within(frame(container)).getByText('edge-1').closest('td')).not.toHaveClass('py-1')
  })

  it('switches from the View menu, is remembered, and every table follows', async () => {
    const { container } = render(
      <>
        <div data-testid="a">
          <DataTable columns={columns} data={data} />
        </div>
        <div data-testid="b">
          <DataTable columns={columns} data={data} showColumnToggle={false} />
        </div>
      </>
    )
    const [viewA] = screen.getAllByRole('button', { name: 'Table view: density and columns' })
    await userEvent.click(viewA)
    await userEvent.click(await screen.findByRole('menuitemradio', { name: 'Compact' }))

    expect(window.localStorage.getItem(TABLE_DENSITY_STORAGE_KEY)).toBe('compact')
    const frames = container.querySelectorAll('[data-density]')
    expect(frames).toHaveLength(2)
    frames.forEach((f) => expect(f).toHaveAttribute('data-density', 'compact'))
  })

  it('keeps the menu even when columns cannot be toggled', async () => {
    render(<DataTable columns={columns} data={data} showColumnToggle={false} />)
    await userEvent.click(screen.getByRole('button', { name: 'Table view: density and columns' }))
    expect(await screen.findByRole('menuitemradio', { name: 'Comfortable' })).toBeInTheDocument()
    expect(screen.queryByText('Columns')).not.toBeInTheDocument()
  })

  it('ignores a garbage stored value and still works when storage throws', async () => {
    window.localStorage.setItem(TABLE_DENSITY_STORAGE_KEY, '<script>')
    const { container, unmount } = render(<DataTable columns={columns} data={data} />)
    // Never the stored garbage: a known density (this page load's choice, or the default).
    expect(frame(container).getAttribute('data-density')).toMatch(/^(compact|comfortable)$/)
    unmount()

    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    const second = render(<DataTable columns={columns} data={data} />)
    await userEvent.click(screen.getByRole('button', { name: 'Table view: density and columns' }))
    await userEvent.click(await screen.findByRole('menuitemradio', { name: 'Compact' }))
    expect(frame(second.container)).toHaveAttribute('data-density', 'compact')
  })
})
