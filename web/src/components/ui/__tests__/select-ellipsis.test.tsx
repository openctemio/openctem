/**
 * A select field is one line, as high as the controls beside it (owner
 * report 2026-11-27: a channel picker wrapped "Product Security channel" onto
 * three lines beside 32 px buttons). A chosen value longer than its field
 * ends in an ellipsis inside its own text box, and that box carries the full
 * text as its title, so nothing chosen is hidden (owner 2026-11-25: "Mọi mức
 * rủi…" with no way to read the rest; the layout matrix's cutMeaning check
 * accepts a cut only with the full text reachable). Text sitting directly in
 * the flex value box cannot end in an ellipsis (a line clamp only works on a
 * `-webkit-box`), so every plain text part of the value gets its own box.
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
  it('the trigger keeps the value on one line and cuts it with an ellipsis', () => {
    const { container } = field({ value: 'long' })
    const cls = container.querySelector('[data-slot="select-trigger"]')!.className
    expect(cls).toContain('whitespace-nowrap')
    expect(cls).toContain('**:data-[slot=select-text]:truncate')
    expect(cls).not.toContain('break-words')
    expect(cls).toContain('data-[size=default]:min-h-control-field')
    expect(cls).not.toMatch(/(^|\s)data-\[size=default\]:h-/)
    expect(cls).toContain('*:data-[slot=select-value]:min-w-0')
    // A line clamp on the flex value box never drew an ellipsis.
    expect(cls).not.toContain('line-clamp')
  })

  it('a chosen text label sits in its own box inside the value, its full text the title', () => {
    const { container } = field({ value: 'long' })
    const text = valueBox(container).querySelector('[data-slot="select-text"]')
    expect(text).toHaveTextContent(LONG)
    expect(text).toHaveAttribute('title', LONG)
    expect(text).toHaveAttribute('data-cut-tooltip')
  })

  it('an icon stays beside the text box, the text alone is cut', () => {
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
