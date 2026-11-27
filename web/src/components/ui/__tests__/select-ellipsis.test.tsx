/**
 * A chosen value longer than its select field wraps: it is never cut, with an
 * ellipsis or without (owner 2026-11-25: "Mọi mức rủi…" hid what the filter
 * holds; the layout matrix's cutMeaning check fails such a cut). Before that,
 * a chosen value ended in an ellipsis, never cut with no mark. Regression (settings review 2026-11-20): scope "One-off
 * entries" in Vietnamese at 390 px showed the value cut mid-word, because the
 * value box was a flex box with `line-clamp-1` (a line clamp only works on a
 * `-webkit-box`, and text sitting directly in a flex box cannot end in an
 * ellipsis). The browser draws the ellipsis; the e2e layout sweep (spec 75)
 * measures it. This pins the structure every select gets from the kit: each
 * plain text part of the value in its own box, and that box wraps; the field
 * keeps its height as a minimum, so a one-line value is drawn as before.
 */
import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../select'

// Radix menus measure their trigger; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const LONG = 'Các mục một lần được duyệt trong phạm vi quét của tổ chức'

function field(props: { value?: string; placeholder?: string; custom?: string }) {
  return render(
    <Select value={props.value}>
      <SelectTrigger className="w-40" aria-label="Entries">
        <SelectValue placeholder={props.placeholder}>{props.custom}</SelectValue>
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="long">{LONG}</SelectItem>
        <SelectItem value="icon">
          <svg data-testid="icon" />
          {LONG}
        </SelectItem>
      </SelectContent>
    </Select>
  )
}

const valueBox = (c: HTMLElement) => c.querySelector('[data-slot="select-value"]') as HTMLElement

describe('Select value ellipsis', () => {
  it('the trigger wraps the value text and lets the value box shrink', () => {
    const { container } = field({ value: 'long' })
    const cls = container.querySelector('[data-slot="select-trigger"]')!.className
    expect(cls).toContain('**:data-[slot=select-text]:break-words')
    expect(cls).not.toContain('truncate')
    expect(cls).not.toContain('whitespace-nowrap')
    // The height is a floor, not a box the second line would spill out of.
    expect(cls).toContain('data-[size=default]:min-h-control-field')
    expect(cls).not.toMatch(/(^|\s)data-\[size=default\]:h-/)
    expect(cls).toContain('*:data-[slot=select-value]:min-w-0')
    // A line clamp on the flex value box never drew an ellipsis.
    expect(cls).not.toContain('line-clamp')
  })

  it('a chosen text label sits in its own box inside the value', () => {
    const { container } = field({ value: 'long' })
    const text = valueBox(container).querySelector('[data-slot="select-text"]')
    expect(text).toHaveTextContent(LONG)
  })

  it('an icon stays beside the text box, the text alone wraps', () => {
    const { container } = field({ value: 'icon' })
    const box = valueBox(container)
    expect(box.querySelector('[data-testid="icon"]')).not.toBeNull()
    expect(box.querySelector('[data-slot="select-text"]')).toHaveTextContent(LONG)
  })

  it('a label built from several text parts is one box (one accessible name)', () => {
    const count = 10
    const { container } = render(
      <Select value="x">
        <SelectTrigger aria-label="Reason">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="x">
            {'Not verified'} ({count})
          </SelectItem>
        </SelectContent>
      </Select>
    )
    const parts = valueBox(container).querySelectorAll('[data-slot="select-text"]')
    expect(parts).toHaveLength(1)
    expect(parts[0]).toHaveTextContent('Not verified (10)')
  })

  it('a placeholder and a custom value text are boxed the same way', () => {
    const empty = field({ placeholder: LONG })
    expect(valueBox(empty.container).querySelector('[data-slot="select-text"]')).toHaveTextContent(
      LONG
    )
    empty.unmount()
    const custom = field({ value: 'long', custom: 'Shown instead' })
    expect(valueBox(custom.container).querySelector('[data-slot="select-text"]')).toHaveTextContent(
      'Shown instead'
    )
  })
})
