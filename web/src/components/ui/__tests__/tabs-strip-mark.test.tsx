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
  it('end on the final geometry after a change that fires no event (a late web font)', () => {
    const fonts = new EventTarget()
    const had = Object.getOwnPropertyDescriptor(document, 'fonts')
    Object.defineProperty(document, 'fonts', { configurable: true, value: fonts })
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
    // The labels widen (no DOM change, no observer yet): the strip overflows.
    Object.defineProperty(strip, 'scrollWidth', { configurable: true, value: 600 })
    Object.defineProperty(strip, 'clientWidth', { configurable: true, value: 300 })
    strip.scrollBy = () => {}
    act(() => {
      fonts.dispatchEvent(new Event('loadingdone'))
    })
    expect(strip.dataset.fadeEnd).toBe('true')
    if (had) Object.defineProperty(document, 'fonts', had)
    else delete (document as { fonts?: unknown }).fonts
  })
})
