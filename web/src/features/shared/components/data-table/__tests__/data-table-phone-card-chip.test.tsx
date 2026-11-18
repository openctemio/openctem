/**
 * A chip value on the automatic phone card is never cut. Acceptance review
 * (2026-11-18): the Vietnamese criticality chip "Trung bình" was clipped to
 * "Trung b" in its half-width field, since a chip has no ellipsis. A field
 * whose chip overflows its half of the line takes the whole line; the other
 * field moves to the line under it and stays shown.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { DataTable } from '../data-table'

type Row = { id: string; name: string; criticality: string; owner: string }

const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
  {
    id: 'criticality',
    header: 'Criticality',
    meta: { label: 'Criticality' },
    cell: ({ row }) => <Badge>{row.original.criticality}</Badge>,
  },
  {
    id: 'owner',
    header: 'Owner',
    meta: { label: 'Owner' },
    cell: ({ row }) => <span>{row.original.owner}</span>,
  },
]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const setWidth = (value: number) =>
  Object.defineProperty(window, 'innerWidth', { configurable: true, value })

// jsdom has no layout: a value cell that holds a chip reports a content width
// wider than its box when the chip text is long.
const proto = HTMLElement.prototype
const saved = {
  scroll: Object.getOwnPropertyDescriptor(proto, 'scrollWidth'),
  client: Object.getOwnPropertyDescriptor(proto, 'clientWidth'),
}
const hasLongChip = (el: HTMLElement) =>
  el.tagName === 'DD' &&
  (el.querySelector('[data-slot=badge],[data-slot$=-badge]')?.textContent ?? '').length > 8

beforeEach(() => {
  setWidth(390)
  Object.defineProperty(proto, 'scrollWidth', {
    configurable: true,
    get(this: HTMLElement) {
      return hasLongChip(this) ? 96 : 60
    },
  })
  Object.defineProperty(proto, 'clientWidth', {
    configurable: true,
    get(this: HTMLElement) {
      return this.tagName === 'DD' ? 72 : 0
    },
  })
})
afterEach(() => {
  setWidth(1440)
  if (saved.scroll) Object.defineProperty(proto, 'scrollWidth', saved.scroll)
  if (saved.client) Object.defineProperty(proto, 'clientWidth', saved.client)
})

const field = (container: HTMLElement, id: string) =>
  container.querySelector<HTMLElement>(`[data-slot="mobile-card-field"][data-column="${id}"]`)

describe('automatic phone card: a chip value is never cut', () => {
  it('gives a field whose chip overflows half the line the whole line', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ id: '1', name: 'web-01', criticality: 'Trung bình', owner: 'Ana' }]}
        getRowId={(r) => r.id}
      />
    )
    expect(field(container, 'criticality')?.className).toContain('col-span-2')
    // The other field is still shown, on the line under it.
    expect(field(container, 'owner')?.textContent).toContain('Ana')
    const dl = container.querySelector('[data-slot="mobile-card"] dl')!
    expect(dl.className).not.toContain('h-5')
    expect(dl.className).toContain('auto-rows-[1.25rem]')
  })

  it('does the same for a named chip that is not the kit Badge', () => {
    const named: ColumnDef<Row>[] = [
      columns[0],
      {
        id: 'criticality',
        header: 'Criticality',
        meta: { label: 'Criticality' },
        cell: ({ row }) => <span data-slot="criticality-badge">{row.original.criticality}</span>,
      },
      columns[2],
    ]
    const { container } = render(
      <DataTable
        columns={named}
        data={[{ id: '1', name: 'web-01', criticality: 'Trung bình', owner: 'Ana' }]}
        getRowId={(r) => r.id}
      />
    )
    expect(field(container, 'criticality')?.className).toContain('col-span-2')
  })

  it('keeps two half-line fields on one line when the chip fits', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ id: '1', name: 'web-01', criticality: 'High', owner: 'Ana' }]}
        getRowId={(r) => r.id}
      />
    )
    expect(field(container, 'criticality')?.className).not.toContain('col-span-2')
    expect(container.querySelector('[data-slot="mobile-card"] dl')?.className).toContain('h-5')
  })
})
