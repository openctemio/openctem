import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { PageHeader } from '@/features/shared/components/page-header'
import { PhoneBarTitle } from '../phone-bar-title'

type Callback = (entries: Partial<IntersectionObserverEntry>[]) => void

let observers: { callback: Callback; options?: IntersectionObserverInit; disconnected: boolean }[] =
  []

beforeEach(() => {
  observers = []
  globalThis.IntersectionObserver = class {
    entry: (typeof observers)[number]
    constructor(callback: Callback, options?: IntersectionObserverInit) {
      this.entry = { callback, options, disconnected: false }
      observers.push(this.entry)
    }
    observe() {}
    unobserve() {}
    disconnect() {
      this.entry.disconnected = true
    }
  } as unknown as typeof IntersectionObserver
})

afterEach(() => {
  // @ts-expect-error jsdom has no IntersectionObserver; drop the stub
  delete globalThis.IntersectionObserver
})

function fire(isIntersecting: boolean, top: number) {
  act(() => {
    observers
      .filter((o) => !o.disconnected)
      .forEach((o) =>
        o.callback([{ isIntersecting, boundingClientRect: { top } as DOMRectReadOnly }])
      )
  })
}

function renderPage(title = 'Findings') {
  return render(
    <>
      <PhoneBarTitle />
      <PageHeader title={title} />
    </>
  )
}

describe('phone bar title (shell package D1)', () => {
  it('shows nothing while the page H1 is in view', () => {
    const { container } = renderPage()
    fire(true, 120)
    expect(container.querySelector('[data-slot=phone-bar-title]')).toBeNull()
    // The H1 is the only visible title.
    expect(screen.getAllByText('Findings')).toHaveLength(1)
  })

  it('repeats the H1 in the bar once it has scrolled under the 48 px bar', () => {
    const { container } = renderPage()
    expect(observers[0]?.options?.rootMargin).toBe('-48px 0px 0px 0px')
    fire(false, -20)
    const slot = container.querySelector('[data-slot=phone-bar-title]')
    expect(slot?.textContent).toBe('Findings')
    // Decorative: the H1 stays the page's one heading for assistive tech.
    expect(slot?.getAttribute('aria-hidden')).toBe('true')
    expect(slot?.className).toContain('text-section')
    expect(slot?.className).toContain('md:hidden')
    // Back in view: gone again.
    fire(true, 60)
    expect(container.querySelector('[data-slot=phone-bar-title]')).toBeNull()
  })

  it('does not show a title for an H1 below the fold', () => {
    const { container } = renderPage()
    fire(false, 900)
    expect(container.querySelector('[data-slot=phone-bar-title]')).toBeNull()
  })

  it('clears the title when the page leaves', () => {
    const { container, rerender } = renderPage()
    fire(false, -20)
    expect(container.querySelector('[data-slot=phone-bar-title]')).not.toBeNull()
    rerender(<PhoneBarTitle />)
    expect(container.querySelector('[data-slot=phone-bar-title]')).toBeNull()
  })
})
