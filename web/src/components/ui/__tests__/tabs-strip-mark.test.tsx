/**
 * A page tab strip marks itself `data-tab-strip`, the mark the layout check
 * (spec 75) reads to let it scroll sideways with its edge fade. The strip is
 * one row on a phone: it never wraps.
 */
import { afterEach, describe, it, expect, vi } from 'vitest'
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
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('measure again when a strip mounted hidden is shown, with no resize report', () => {
    // A strip that mounts hidden (inside a settle group) measures 0 px; the
    // reveal may bring no resize callback. The intersection observer's does.
    let reveal: () => void = () => {}
    vi.stubGlobal(
      'IntersectionObserver',
      class {
        constructor(cb: () => void) {
          reveal = cb
        }
        observe() {}
        disconnect() {}
      }
    )
    const { container } = render(
      <Tabs defaultValue="a">
        <TabsList>
          <TabsTrigger value="a">A</TabsTrigger>
          <TabsTrigger value="b">B</TabsTrigger>
        </TabsList>
      </Tabs>
    )
    const strip = container.querySelector<HTMLElement>('[data-slot="tabs-list"]')!
    expect(strip.dataset.fadeEnd).toBe('false')
    // Shown: the tabs overflow the strip.
    Object.defineProperty(strip, 'scrollWidth', { configurable: true, value: 600 })
    Object.defineProperty(strip, 'clientWidth', { configurable: true, value: 300 })
    strip.scrollBy = () => {}
    act(() => reveal())
    expect(strip.dataset.fadeEnd).toBe('true')
  })
})
