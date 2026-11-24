/**
 * A page tab strip marks itself `data-tab-strip`, the mark the layout check
 * (spec 75) reads to let it scroll sideways with its edge fade. The strip is
 * one row on a phone: it never wraps.
 */
import { describe, it, expect } from 'vitest'
import { act, render } from '@testing-library/react'
import { Tabs, TabsList, TabsTrigger, TAB_STRIP_CLASS } from '../tabs'

describe('page tab strip', () => {
  it('marks itself as a tab strip', () => {
    const { container } = render(
      <Tabs defaultValue="a">
        <TabsList>
          <TabsTrigger value="a">A</TabsTrigger>
          <TabsTrigger value="b">B</TabsTrigger>
        </TabsList>
      </Tabs>
    )
    expect(container.querySelector('[data-slot="tabs-list"]')).toHaveAttribute('data-tab-strip')
  })

  it('is one row that scrolls sideways, snaps, and fades both ways of reading', () => {
    expect(TAB_STRIP_CLASS).toContain('overflow-x-auto')
    expect(TAB_STRIP_CLASS).toContain('snap-x')
    expect(TAB_STRIP_CLASS).not.toContain('flex-wrap')
    expect(TAB_STRIP_CLASS).toContain('rtl:data-[fade-end=true]')
  })
})

describe('page tab strip edge marks', () => {
  it('measure again at once when a strip mounted hidden is shown', async () => {
    // A strip that mounts hidden (inside a settle group) measures 0 px. When
    // its wrapper is shown the marks follow before the next frame.
    const { container } = render(
      <div hidden data-testid="wrap">
        <Tabs defaultValue="a">
          <TabsList>
            <TabsTrigger value="a">A</TabsTrigger>
            <TabsTrigger value="b">B</TabsTrigger>
          </TabsList>
        </Tabs>
      </div>
    )
    const strip = container.querySelector<HTMLElement>('[data-slot="tabs-list"]')!
    expect(strip.dataset.fadeEnd).toBe('false')
    // Shown: the tabs overflow the strip.
    Object.defineProperty(strip, 'scrollWidth', { configurable: true, value: 600 })
    Object.defineProperty(strip, 'clientWidth', { configurable: true, value: 300 })
    strip.scrollBy = () => {}
    await act(async () => {
      ;(container.querySelector('[data-testid="wrap"]') as HTMLElement).hidden = false
      await Promise.resolve()
    })
    expect(strip.dataset.fadeEnd).toBe('true')
  })
})
