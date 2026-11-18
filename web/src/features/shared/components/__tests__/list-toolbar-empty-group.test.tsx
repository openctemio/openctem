/**
 * A toolbar group that draws none of its controls takes no line. Acceptance
 * review (2026-11-18): on a phone the CVE catalog toolbar kept an empty end
 * group (the Display menu is hidden at that width) on a wrapped line of its
 * own; the first filter chip then shared that line, so adding a filter moved
 * the list by 36 px instead of the 44 of a new line (spec 35).
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { ListToolbar } from '../list-toolbar'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

// jsdom has no layout: an element inside `.phone-hidden` draws nothing, every
// other element a 36 px box.
const proto = Element.prototype
const saved = Object.getOwnPropertyDescriptor(proto, 'getClientRects')
beforeEach(() => {
  Object.defineProperty(proto, 'getClientRects', {
    configurable: true,
    value(this: Element) {
      return this.closest('.phone-hidden') ? [] : [{ width: 36, height: 36 }]
    },
  })
})
afterEach(() => {
  if (saved) Object.defineProperty(proto, 'getClientRects', saved)
})

const group = (c: HTMLElement, slot: string) =>
  c.querySelector<HTMLElement>(`[data-slot="list-toolbar-${slot}"]`)!

describe('list toolbar: a group that draws nothing takes no line', () => {
  it('takes the end group out of the flow while its controls are hidden', () => {
    const { container } = render(
      <ListToolbar
        end={
          <button type="button" className="phone-hidden">
            Display
          </button>
        }
      />
    )
    const end = group(container, 'end')
    expect(end).toHaveAttribute('data-empty')
    expect(end.className).toContain('data-[empty]:absolute')
  })

  it('does the same for a tokens strip whose selects moved into the Filters sheet', () => {
    const { container } = render(
      <ListToolbar
        filter={<button type="button">Filters</button>}
        start={<span className="phone-hidden">Status: Open</span>}
      />
    )
    expect(group(container, 'tokens')).toHaveAttribute('data-empty')
  })

  it('leaves a group that draws a control in the flow', () => {
    const { container } = render(<ListToolbar end={<button type="button">Export</button>} />)
    expect(group(container, 'end')).not.toHaveAttribute('data-empty')
  })
})
