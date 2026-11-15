/**
 * Column priority: a column whose `meta.hideBelow` is wider than the table's
 * frame is hidden, unless the viewer chose it under Columns; without a
 * measured frame every column shows.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { VisibilityState } from '@tanstack/react-table'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { name: string; owner: string; seen: string }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', enableHiding: false },
  { id: 'owner', accessorKey: 'owner', header: 'Owner', meta: { hideBelow: 800, label: 'Owner' } },
  // No explicit id: the accessor key names it.
  { accessorKey: 'seen', header: 'Last seen', meta: { hideBelow: 1000, label: 'Last seen' } },
]
const rows = [{ name: 'a', owner: 'o', seen: 's' }]

let frame = 0
const saved = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth')

beforeEach(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
    configurable: true,
    get(this: HTMLElement) {
      return this.dataset.density !== undefined ? frame : 0
    },
  })
  vi.stubGlobal(
    'ResizeObserver',
    class {
      constructor(private cb: (entries: unknown[]) => void) {}
      observe() {
        this.cb([])
      }
      disconnect() {}
      unobserve() {}
    }
  )
})

afterEach(() => {
  if (saved) Object.defineProperty(HTMLElement.prototype, 'clientWidth', saved)
  vi.unstubAllGlobals()
})

const headers = () => screen.getAllByRole('columnheader').map((h) => h.textContent)

describe('DataTable column priority (meta.hideBelow)', () => {
  it('hides the columns the frame has no room for, keeps the rest', () => {
    frame = 900
    render(<DataTable columns={columns} data={rows} mobileCards={false} />)
    expect(headers()).toEqual(['Name', 'Owner'])
  })

  it('a wide frame shows every column', () => {
    frame = 1200
    render(<DataTable columns={columns} data={rows} mobileCards={false} />)
    expect(headers()).toEqual(['Name', 'Owner', 'Last seen'])
  })

  it('a column the viewer turned on stays on in a narrow frame', () => {
    frame = 700
    render(
      <DataTable
        columns={columns}
        data={rows}
        mobileCards={false}
        initialColumnVisibility={{ seen: true }}
      />
    )
    expect(headers()).toEqual(['Name', 'Last seen'])
  })

  it('without a measured frame nothing is hidden by priority', () => {
    frame = 0
    render(<DataTable columns={columns} data={rows} mobileCards={false} />)
    expect(headers()).toEqual(['Name', 'Owner', 'Last seen'])
  })

  it('a controlled table (every column named) still drops columns on a narrow frame', () => {
    frame = 900
    render(
      <DataTable
        columns={columns}
        data={rows}
        mobileCards={false}
        columnVisibility={{ owner: true, seen: true }}
        onColumnVisibilityChange={() => {}}
      />
    )
    expect(headers()).toEqual(['Name', 'Owner'])
  })

  it('a click on an auto-hidden column shows it; the page keeps its own values', async () => {
    frame = 700
    const changes: VisibilityState[] = []
    render(
      <DataTable
        columns={columns}
        data={rows}
        mobileCards={false}
        columnVisibility={{ owner: true, seen: true }}
        onColumnVisibilityChange={(v) => changes.push(v)}
      />
    )
    expect(headers()).toEqual(['Name'])
    await userEvent.click(screen.getByRole('button', { name: /display/i }))
    const owner = await screen.findByRole('menuitemcheckbox', { name: 'Owner' })
    expect(owner).toHaveAttribute('aria-checked', 'false')
    await userEvent.click(owner)
    expect(headers()).toEqual(['Name', 'Owner'])
    // The width's choice for Last seen never reaches the page.
    expect(changes.at(-1)).toEqual({ owner: true, seen: true })
  })
})
