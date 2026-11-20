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

// jsdom has no layout: an element inside `.phone-hidden` draws nothing, a
// shape inside an icon a line with no area (as an icon's strokes measure), every
// other element a 36 px box.
const proto = Element.prototype
const saved = Object.getOwnPropertyDescriptor(proto, 'getClientRects')
beforeEach(() => {
  Object.defineProperty(proto, 'getClientRects', {
    configurable: true,
    value(this: Element) {
      if (this.closest('.phone-hidden')) return []
      if (this.tagName.toLowerCase() === 'path') return [{ width: 12, height: 0 }]
      return [{ width: 36, height: 36 }]
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

  it('leaves an icon-only control in the flow: its icon draws, though its strokes have no area', () => {
    // A tokens strip holding only the icon-only Add filter (a desktop list
    // whose value tokens are chips) was marked empty: no pointer events
    // reached the button.
    const { container } = render(
      <ListToolbar
        start={
          <button type="button" aria-label="Add filter">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M2 6h16" />
              <path d="M18 9v6" />
            </svg>
          </button>
        }
      />
    )
    expect(group(container, 'tokens')).not.toHaveAttribute('data-empty')
  })

  it('gives the chips the whole second line on a phone while the tokens are out of the flow', () => {
    const { container } = render(
      <ListToolbar
        search={{ value: '', onChange: () => {}, placeholder: 'Search things' }}
        start={<span className="phone-hidden">Status: Open</span>}
        end={<button type="button">Export</button>}
        below={<span>chip</span>}
      />
    )
    expect(group(container, 'tokens')).toHaveAttribute('data-empty')
    // The end group keeps its own column on the search line, whatever the tokens do.
    expect(group(container, 'end').className).toContain('@max-md/toolbar:col-start-3')
    expect(group(container, 'end').className).toContain('@max-md/toolbar:row-start-1')
    // Normally after the tokens (columns 2-3); from the line's start once they draw nothing.
    const below = container.querySelector('[data-slot="list-toolbar-below"]')!.className
    expect(below).toContain('@max-md/toolbar:col-end-4')
    expect(below).toContain(
      '@max-md/toolbar:group-has-[[data-slot=list-toolbar-tokens][data-empty]]/toolbar:col-start-1'
    )
  })
})
