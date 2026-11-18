/**
 * The automatic phone card counts a switch as a value: a field whose cell is
 * only a switch ("Enabled") reads "On" or "Off" beside it and follows the
 * switch when it changes. Regression: /scans/workflows at 390 px showed the
 * "Enabled" label over a bare switch (e2e 66-phone-card-bounds, "labels
 * without a value").
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { act, render } from '@testing-library/react'
import * as React from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Switch } from '@/components/ui/switch'
import { DataTable } from '../data-table'

type Row = { id: string; name: string; enabled: boolean; note: string }

function Toggle({ initial }: { initial: boolean }) {
  const [on, setOn] = React.useState(initial)
  return <Switch aria-label="Enabled" checked={on} onCheckedChange={setOn} />
}

const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
  {
    id: 'enabled',
    header: 'Enabled',
    meta: { kind: 'text', label: 'Enabled' },
    cell: ({ row }) => <Toggle initial={row.original.enabled} />,
  },
  {
    id: 'note',
    header: 'Note',
    meta: { kind: 'text', label: 'Note' },
    cell: ({ row }) => (
      <span className="flex items-center gap-2">
        <Switch aria-label="Notify" checked />
        {row.original.note}
      </span>
    ),
  },
]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const setWidth = (value: number) =>
  Object.defineProperty(window, 'innerWidth', { configurable: true, value })

beforeEach(() => setWidth(390))
afterEach(() => setWidth(1440))

const fieldValue = (container: HTMLElement, label: string) => {
  const field = Array.from(container.querySelectorAll('[data-slot="mobile-card-field"]')).find(
    (f) => f.querySelector('dt')?.textContent === label
  )
  return field?.querySelector('dd') ?? null
}

describe('automatic phone card: a switch is a value', () => {
  it('writes On or Off beside a switch that is the whole value, and follows it', async () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[
          { id: '1', name: 'Nightly', enabled: true, note: 'mail' },
          { id: '2', name: 'Weekly', enabled: false, note: 'mail' },
        ]}
        getRowId={(r) => r.id}
      />
    )
    const cards = container.querySelectorAll('[data-slot="mobile-card"]')
    expect(cards).toHaveLength(2)
    const first = fieldValue(cards[0] as HTMLElement, 'Enabled')
    const second = fieldValue(cards[1] as HTMLElement, 'Enabled')
    expect(first?.textContent).toBe('On')
    expect(second?.textContent).toBe('Off')
    // The word is for the eye; the switch keeps its own name and state.
    expect(first?.querySelector('[data-slot="card-switch-text"]')).toHaveAttribute(
      'aria-hidden',
      'true'
    )

    await act(async () => {
      ;(second?.querySelector('[role=switch]') as HTMLElement).click()
    })
    expect(second?.textContent).toBe('On')
  })

  it('adds nothing beside a switch that has text of its own', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ id: '1', name: 'Nightly', enabled: true, note: 'mail' }]}
        getRowId={(r) => r.id}
      />
    )
    const note = fieldValue(container, 'Note')
    expect(note?.textContent).toBe('mail')
    expect(note?.querySelector('[data-slot="card-switch-text"]')).toBeNull()
  })
})
