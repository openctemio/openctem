/**
 * The automatic phone card's title line (acceptance review 2026-11-18):
 * - the title is the row's name column (kind `name`), never the first column
 *   by position or a value guessed from the cells;
 * - a name cell sized for the table (`w-0 min-w-full`, as on the asset
 *   groups list) still shows its name: the card gives it its own width and
 *   two lines (the name was clipped out of a 20 px line);
 * - nothing wraps under the title: a status cell too wide for the title line
 *   gets a line of its own, and an actions cell wider than one icon button
 *   moves to one trailing line at the card's end (the scan workflows list
 *   left a tall empty band and cut its chips at the card edge);
 * - "0" is a value and stays a field.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string; env: string; findings: number; owner: string }

const row: Row = { id: '1', name: 'Web', env: 'Production', findings: 0, owner: 'Blue team' }

const columns = (actions: React.ReactNode): ColumnDef<Row>[] => [
  { accessorKey: 'owner', header: 'Owner', meta: { label: 'Owner' } },
  {
    accessorKey: 'name',
    header: 'Name',
    meta: { kind: 'name', label: 'Name' },
    cell: ({ row: r }) => (
      <div data-testid="name-cell" className="flex w-0 min-w-full items-center">
        <a href="/x" className="block truncate">
          {r.original.name}
        </a>
      </div>
    ),
  },
  {
    accessorKey: 'env',
    header: 'Environment',
    meta: { kind: 'status', label: 'Environment' },
    cell: ({ row: r }) => (
      <span data-testid="status-chip">
        {r.original.env} <span>Runs in your sensors</span>
      </span>
    ),
  },
  { accessorKey: 'findings', header: 'Findings', meta: { kind: 'number', label: 'Findings' } },
  { id: 'actions', meta: { kind: 'actions' }, cell: () => actions },
]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const setWidth = (value: number) =>
  Object.defineProperty(window, 'innerWidth', { configurable: true, value })

beforeEach(() => setWidth(390))
afterEach(() => {
  setWidth(1440)
  vi.restoreAllMocks()
})

const slot = (c: HTMLElement, name: string) =>
  c.querySelector<HTMLElement>(`[data-slot="mobile-card-${name}"]`)

const menu = <button type="button" aria-label="Actions for Web" />

describe('automatic phone card: the title line', () => {
  it('takes the title from the name column, not the first column', () => {
    const { container } = render(<DataTable columns={columns(menu)} data={[row]} />)
    expect(slot(container, 'title')?.textContent).toBe('Web')
    expect(slot(container, 'title')?.querySelector('[data-testid="name-cell"]')).not.toBeNull()
  })

  it('gives a name cell sized for the table the card width and two lines', () => {
    const { container } = render(<DataTable columns={columns(menu)} data={[row]} />)
    const title = slot(container, 'title')!
    // The cell's own w-0 gives way to the card (it hid the name), and the
    // name wraps to two lines instead of being cut on one 20 px line.
    expect(title.className).toContain('[&>*]:w-auto')
    expect(title.className).toContain('[&_a]:line-clamp-2')
    expect(title.className).toContain('max-h-10')
    // A word longer than the card (an e-mail address) breaks and does not set
    // the title's minimum width (break-word did: it ran under the menu button).
    expect(title.className).toContain('[overflow-wrap:anywhere]')
    expect(title.className).not.toMatch(/(^|\s)h-5(\s|$)/)
  })

  it('never wraps the title line', () => {
    const { container } = render(<DataTable columns={columns(menu)} data={[row]} />)
    const head = slot(container, 'head')!
    expect(head.className).not.toContain('flex-wrap')
    expect(head.contains(slot(container, 'title'))).toBe(true)
    // One icon button stays on the title line.
    expect(head.contains(slot(container, 'actions'))).toBe(true)
  })

  it('centres a chip control and the row menu on one line at one height', () => {
    // The scan workflows list: a 25 px chip that opens a popover sat beside
    // the 36 px row menu on another centre line (page-rhythm probeRowMix).
    const chipColumns = columns(menu).map((c) =>
      (c.meta as { kind?: string } | undefined)?.kind === 'status'
        ? {
            ...c,
            cell: () => (
              <button type="button" data-testid="chip-control">
                <span data-slot="badge">Not ready</span>
              </button>
            ),
          }
        : c
    )
    const { container } = render(<DataTable columns={chipColumns} data={[row]} />)
    const head = slot(container, 'head')!
    expect(head.className).toMatch(/(^|\s)items-center(\s|$)/)
    expect(head.className).not.toContain('items-start')
    const status = slot(container, 'status')!
    const actions = slot(container, 'actions')!
    expect(head.contains(status)).toBe(true)
    // Both boxes are the menu's 36 px, pulled out of the 20 px line so the
    // line does not grow; a control in the status takes the same box.
    for (const el of [status, actions]) {
      expect(el.className).toMatch(/(^|\s)h-9(\s|$)/)
      expect(el.className).toMatch(/(^|\s)-my-2(\s|$)/)
      expect(el.className).toMatch(/(^|\s)items-center(\s|$)/)
    }
    expect(status.className).toContain('[&_button:not([role=switch])]:h-9')
    expect(status.className).toContain('[&_button:not([role=switch])]:items-center')
    expect(status.querySelector('[data-testid="chip-control"]')).not.toBeNull()
  })

  it('moves an actions cell wider than one icon button to a trailing line', () => {
    const real = HTMLElement.prototype.getBoundingClientRect
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (
      this: HTMLElement
    ) {
      if (this.getAttribute('data-slot') === 'mobile-card-actions') {
        return {
          width: 180,
          height: 32,
          top: 0,
          left: 0,
          right: 180,
          bottom: 32,
          x: 0,
          y: 0,
          toJSON() {},
        } as DOMRect
      }
      return real.call(this)
    })
    const wide = (
      <>
        <button type="button">Run now</button>
        <button type="button">Edit</button>
      </>
    )
    const { container } = render(<DataTable columns={columns(wide)} data={[row]} />)
    const actions = slot(container, 'actions')!
    expect(slot(container, 'head')!.contains(actions)).toBe(false)
    // The last line of the card, after the fields.
    expect(actions.parentElement?.lastElementChild).toBe(actions)
    expect(actions.className).not.toContain('flex-wrap')
  })

  it('gives a status cell too wide for the title line a line of its own', () => {
    const sw = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollWidth')
    const cw = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth')
    const isStatus = (el: HTMLElement) => el.getAttribute('data-slot') === 'mobile-card-status'
    Object.defineProperty(HTMLElement.prototype, 'scrollWidth', {
      configurable: true,
      get(this: HTMLElement) {
        return isStatus(this) ? 240 : 0
      },
    })
    Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
      configurable: true,
      get(this: HTMLElement) {
        return isStatus(this) ? 160 : 0
      },
    })
    try {
      const { container } = render(<DataTable columns={columns(menu)} data={[row]} />)
      const status = slot(container, 'status')!
      expect(slot(container, 'head')!.contains(status)).toBe(false)
      expect(status.textContent).toContain('Runs in your sensors')
    } finally {
      if (sw) Object.defineProperty(HTMLElement.prototype, 'scrollWidth', sw)
      if (cw) Object.defineProperty(HTMLElement.prototype, 'clientWidth', cw)
    }
  })

  it('keeps "0" as a field value', () => {
    const { container } = render(<DataTable columns={columns(menu)} data={[row]} />)
    const fields = Array.from(
      container.querySelectorAll<HTMLElement>('[data-slot="mobile-card-field"]')
    ).map((f) => `${f.querySelector('dt')?.textContent}=${f.querySelector('dd')?.textContent}`)
    expect(fields).toContain('Findings=0')
  })
})
