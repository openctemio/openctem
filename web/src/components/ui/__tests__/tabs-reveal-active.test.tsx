/**
 * A strip that scrolls sideways fades its edges over 2.5rem (40 px) where more
 * tabs are hidden. The active tab is scrolled into full view, also when it is
 * inside the strip's box but under that fade.
 */
import * as React from 'react'
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render } from '@testing-library/react'
import { useTabStripScroll } from '../tabs'

type Box = { left: number; right: number }

function rect({ left, right }: Box): DOMRect {
  const width = right - left
  return { left, right, width, top: 0, bottom: 40, height: 40, x: left, y: 0, toJSON: () => ({}) }
}

/** A 358 px strip with 600 px of tabs, scrolled to `scrollLeft`; the active tab sits at `active`. */
function Strip({
  scrollLeft,
  active,
  onScrollBy,
}: {
  scrollLeft: number
  active: Box
  onScrollBy: (l: number) => void
}) {
  const ref = React.useRef<HTMLDivElement | null>(null)
  const setRef = (el: HTMLDivElement | null) => {
    if (el && !ref.current) {
      Object.defineProperty(el, 'scrollWidth', { value: 600, configurable: true })
      Object.defineProperty(el, 'clientWidth', { value: 358, configurable: true })
      Object.defineProperty(el, 'scrollLeft', { value: scrollLeft, configurable: true })
      el.getBoundingClientRect = () => rect({ left: 0, right: 358 })
      el.scrollBy = ((o: ScrollToOptions) => onScrollBy(o.left ?? 0)) as typeof el.scrollBy
      const tab = el.querySelector<HTMLElement>('[data-state="active"]')
      if (tab) tab.getBoundingClientRect = () => rect(active)
    }
    ref.current = el
  }
  useTabStripScroll(ref)
  return (
    <div ref={setRef}>
      <button data-state="inactive">Overview</button>
      <button data-state="active">Activity</button>
    </div>
  )
}

afterEach(() => vi.restoreAllMocks())

describe('useTabStripScroll reveals the active tab', () => {
  it('scrolls a tab that sits under the end fade (inside the box, half hidden)', () => {
    const onScrollBy = vi.fn()
    render(<Strip scrollLeft={0} active={{ left: 290, right: 350 }} onScrollBy={onScrollBy} />)
    expect(onScrollBy).toHaveBeenCalled()
    expect(onScrollBy.mock.calls[0][0]).toBeGreaterThan(0)
  })

  it('scrolls a tab that sits under the start fade', () => {
    const onScrollBy = vi.fn()
    render(<Strip scrollLeft={120} active={{ left: 8, right: 70 }} onScrollBy={onScrollBy} />)
    expect(onScrollBy).toHaveBeenCalled()
    expect(onScrollBy.mock.calls[0][0]).toBeLessThan(0)
  })

  it('leaves a tab alone when it is clear of both fades', () => {
    const onScrollBy = vi.fn()
    render(<Strip scrollLeft={120} active={{ left: 120, right: 200 }} onScrollBy={onScrollBy} />)
    expect(onScrollBy).not.toHaveBeenCalled()
  })

  it('leaves the last tab alone at the end of the strip, where the end fade is off', () => {
    const onScrollBy = vi.fn()
    render(<Strip scrollLeft={242} active={{ left: 290, right: 356 }} onScrollBy={onScrollBy} />)
    expect(onScrollBy).not.toHaveBeenCalled()
  })
})
