/**
 * A list that fails to load shows the shared error block inside its frame:
 * start-aligned like every alert (icon, title, sentence and buttons share one
 * edge), the board's wording ("Couldn't load ...", "Nothing was changed."),
 * never the server's bare code. Regression (acceptance review 2026-11-18): the
 * table cell centred the title and sentence while the icon and the buttons
 * stayed at the start, the title read "Failed to load ...", and a 500 printed
 * "internal".
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string }

const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function serverError() {
  return Object.assign(new Error('internal'), { statusCode: 500 })
}

describe('DataTable load error block', () => {
  it('is start-aligned inside the frame, never centred', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[]}
        error={serverError()}
        errorTitle="sensors"
        onRetry={vi.fn()}
      />
    )
    const cell = container.querySelector('[data-slot="table-error-cell"]')
    expect(cell).not.toBeNull()
    expect(cell!.className).toContain('text-start')
    expect(cell!.className).not.toContain('text-center')
    // As tall as the alert: no fixed height leaving an empty band under it.
    expect(cell!.className).not.toMatch(/(^|\s)h-\d/)
    expect(cell!.querySelector('[role="alert"]')).not.toBeNull()
  })

  it("reads Couldn't load and Nothing was changed, never the bare server code", () => {
    render(
      <DataTable
        columns={columns}
        data={[]}
        error={serverError()}
        errorTitle="sensors"
        onRetry={vi.fn()}
      />
    )
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent("Couldn't load sensors")
    expect(alert).toHaveTextContent('Nothing was changed.')
    expect(alert.textContent).not.toMatch(/(^|\s)internal(\s|$)/)
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('keeps the empty state centred', () => {
    const { container } = render(<DataTable columns={columns} data={[]} />)
    expect(container.querySelector('[data-slot="table-error-cell"]')).toBeNull()
  })
})
