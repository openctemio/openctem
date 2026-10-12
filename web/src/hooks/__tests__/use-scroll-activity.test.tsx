import { render } from '@testing-library/react'
import { useRef } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useScrollActivity } from '../use-scroll-activity'

function Scroller() {
  const ref = useRef<HTMLDivElement>(null)
  useScrollActivity(ref, 500)
  return <div ref={ref} data-testid="scroller" />
}

describe('useScrollActivity', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('sets data-scrolling while scrolling and clears it when idle', () => {
    const { getByTestId } = render(<Scroller />)
    const el = getByTestId('scroller')
    expect(el.hasAttribute('data-scrolling')).toBe(false)

    el.dispatchEvent(new Event('scroll'))
    expect(el.hasAttribute('data-scrolling')).toBe(true)

    vi.advanceTimersByTime(400)
    el.dispatchEvent(new Event('scroll'))
    vi.advanceTimersByTime(400)
    expect(el.hasAttribute('data-scrolling')).toBe(true)

    vi.advanceTimersByTime(200)
    expect(el.hasAttribute('data-scrolling')).toBe(false)
  })

  it('removes the attribute on unmount', () => {
    const { getByTestId, unmount } = render(<Scroller />)
    const el = getByTestId('scroller')
    el.dispatchEvent(new Event('scroll'))
    unmount()
    expect(el.hasAttribute('data-scrolling')).toBe(false)
  })
})
