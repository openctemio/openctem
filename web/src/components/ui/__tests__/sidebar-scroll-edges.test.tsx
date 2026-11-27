/**
 * The nav scroller under the organization switcher: a row cut by its top or
 * bottom edge is faded (data-fade-top / data-fade-bottom) so it reads as
 * "more this way", and a row reached by Tab stops clear of the fade
 * (scroll padding). The sheet over the page (768-1023 px) focuses the current
 * page's row without the browser's edge scroll and centres it instead.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { act, render, screen } from '@testing-library/react'
import { SidebarContent, SidebarProvider } from '../sidebar'

function sized(el: HTMLElement, { scrollHeight, clientHeight }: Record<string, number>) {
  Object.defineProperty(el, 'scrollHeight', { configurable: true, value: scrollHeight })
  Object.defineProperty(el, 'clientHeight', { configurable: true, value: clientHeight })
}

describe('SidebarContent edge fade', () => {
  it('fades the edge that has rows hidden behind it', () => {
    render(
      <SidebarProvider>
        <SidebarContent data-testid="nav">
          <div>rows</div>
        </SidebarContent>
      </SidebarProvider>
    )
    const nav = screen.getByTestId('nav')
    // At rest at the top of a list taller than the column: only the bottom fades.
    sized(nav, { scrollHeight: 1200, clientHeight: 600 })
    act(() => {
      nav.scrollTop = 0
      nav.dispatchEvent(new Event('scroll'))
    })
    expect(nav.dataset.fadeTop).toBe('false')
    expect(nav.dataset.fadeBottom).toBe('true')
    // Scrolled half-way: both edges fade.
    act(() => {
      nav.scrollTop = 300
      nav.dispatchEvent(new Event('scroll'))
    })
    expect(nav.dataset.fadeTop).toBe('true')
    expect(nav.dataset.fadeBottom).toBe('true')
    // At the end: only the top fades.
    act(() => {
      nav.scrollTop = 600
      nav.dispatchEvent(new Event('scroll'))
    })
    expect(nav.dataset.fadeTop).toBe('true')
    expect(nav.dataset.fadeBottom).toBe('false')
  })

  it('draws the fade as a mask and keeps Tab stops clear of it', () => {
    render(
      <SidebarProvider>
        <SidebarContent data-testid="nav" />
      </SidebarProvider>
    )
    const cls = screen.getByTestId('nav').className
    expect(cls).toContain('data-[fade-top=true]:[mask-image:')
    expect(cls).toContain('data-[fade-bottom=true]:[mask-image:')
    expect(cls).toContain('scroll-py-6')
  })
})

describe('sidebar sheet over the page', () => {
  it('focuses the current row without the edge scroll, then centres it', () => {
    const src = readFileSync(path.resolve(__dirname, '../sidebar.tsx'), 'utf8')
    expect(src).toContain('row.focus({ preventScroll: true })')
    expect(src).toContain("row.scrollIntoView({ block: 'center', inline: 'nearest' })")
  })
})
