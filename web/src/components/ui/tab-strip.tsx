'use client'

// The tab strip's look and scroll behaviour, without the tabs primitive:
// route-link strips (SectionTabs) and other sideways-scrolling rows use these
// without downloading the tabs component. components/ui/tabs.tsx re-exports
// everything here.
import * as React from 'react'

import { cn } from '@/lib/utils'
import { formatNumber } from '@/lib/app-locale'

/**
 * The underline tab strip, shared by `TabsList` and route-link strips
 * (`SectionTabs`) so both look identical. It scrolls sideways when the tabs do
 * not fit; the fade on an edge (see `useTabStripScroll`) says more are hidden.
 * Tabs sit 20px apart on a phone (24px from `sm`): three tabs with counts fit
 * a 390px phone instead of cutting the last label by a few pixels.
 */
/**
 * The edge fade of a row that scrolls sideways: an edge with hidden items
 * fades out. `useTabStripScroll` sets the `data-fade-start` / `data-fade-end`
 * it reads. Shared by the tab strips and the filter chips row on a phone.
 */
export const EDGE_FADE_X_CLASS = [
  'data-[fade-end=true]:[mask-image:linear-gradient(to_right,black_calc(100%-2.5rem),transparent)]',
  'data-[fade-start=true]:[mask-image:linear-gradient(to_right,transparent,black_2.5rem)]',
  'data-[fade-start=true]:data-[fade-end=true]:[mask-image:linear-gradient(to_right,transparent,black_2.5rem,black_calc(100%-2.5rem),transparent)]',
  // Right to left: the start edge is the right one, so the gradients turn round.
  'rtl:data-[fade-end=true]:[mask-image:linear-gradient(to_left,black_calc(100%-2.5rem),transparent)]',
  'rtl:data-[fade-start=true]:[mask-image:linear-gradient(to_left,transparent,black_2.5rem)]',
  'rtl:data-[fade-start=true]:data-[fade-end=true]:[mask-image:linear-gradient(to_left,transparent,black_2.5rem,black_calc(100%-2.5rem),transparent)]',
].join(' ')

/** The fade in `EDGE_FADE_X_CLASS` is 2.5rem wide; in px for the scroll hook. */
function edgeFadeWidth(): number {
  const rem = parseFloat(getComputedStyle(document.documentElement).fontSize)
  return (Number.isFinite(rem) && rem > 0 ? rem : 16) * 2.5
}

export const TAB_STRIP_CLASS = `flex h-10 w-full max-w-full items-stretch justify-start gap-5 overflow-x-auto sm:gap-6 overflow-y-hidden overscroll-x-contain snap-x snap-proximity border-b text-muted-foreground no-scrollbar ${EDGE_FADE_X_CLASS}`

/** One underline tab in a `TAB_STRIP_CLASS` strip. */
export const TAB_CLASS =
  // The active underline is an inset shadow drawn inside the tab, right on top
  // of the strip's border. It used to be a border pulled down 1px (-mb-px),
  // which made every strip 1px taller than its box: on iOS that let the strip
  // scroll vertically and the tabs wobbled under a finger. shrink-0 keeps
  // labels whole; the strip scrolls sideways instead.
  'inline-flex shrink-0 snap-start items-center justify-center gap-1.5 whitespace-nowrap px-0.5 text-sm font-medium transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 data-[state=active]:text-foreground data-[state=active]:shadow-[inset_0_-2px_0_var(--foreground)] aria-[current=page]:text-foreground aria-[current=page]:shadow-[inset_0_-2px_0_var(--foreground)] [&_svg]:size-4 [&_svg]:shrink-0' // design-ok: existing underline shadow and text size, moved only by snap-start

/**
 * Keeps a horizontally scrolling tab strip usable on narrow screens: marks
 * which edges have hidden tabs (drives the fade), and scrolls the active tab
 * (`data-state=active` or `aria-current=page`) into view on load and whenever
 * it changes, so a tab past the edge is never selected but invisible.
 */
export function useTabStripScroll(
  ref: React.RefObject<HTMLElement | null>,
  /** Re-attach when this changes (a strip that mounts after its owner). */
  attachKey?: unknown
) {
  React.useEffect(() => {
    const el = ref.current
    if (!el) return
    // Marks a page tab strip: a scroller whose edge fade is the cue that more
    // tabs are hidden, so the layout checks let it scroll (a toolbar may not).
    el.dataset.tabStrip = ''
    const update = () => {
      const x = Math.abs(el.scrollLeft)
      const max = el.scrollWidth - el.clientWidth
      el.dataset.fadeStart = String(x > 1)
      el.dataset.fadeEnd = String(max - x > 1)
    }
    const revealActive = () => {
      const active = el.querySelector<HTMLElement>('[data-state="active"], [aria-current="page"]')
      if (!active) return
      const a = active.getBoundingClientRect()
      const s = el.getBoundingClientRect()
      // An edge with more tabs behind it fades over its last 2.5rem: a tab
      // under that fade is half hidden, so it counts as out of view too.
      const x = Math.abs(el.scrollLeft)
      const max = el.scrollWidth - el.clientWidth
      const fade = edgeFadeWidth()
      const start = s.left + (x > 1 ? fade : 0)
      const end = s.right - (max - x > 1 ? fade : 0)
      if (a.left < start || a.right > end) {
        // Centred (the browser clamps at the ends): a tab near the end then
        // brings the strip to its end, where the fade is off.
        el.scrollBy({ left: a.left - s.left - (s.width - a.width) / 2, behavior: 'auto' })
      }
      update()
    }
    revealActive()
    update()
    el.addEventListener('scroll', update, { passive: true })
    // The strip keeps its own size when a tab grows (a count arrives, a label
    // is translated, a web font loads), so each tab is observed too: watching
    // only the strip left the end fade off while the last tab was cut.
    // When the strip's own width changes the active tab is revealed again: a
    // strip mounted while hidden (inside a `SettleGroup` that has not settled,
    // a closed sheet) measures 0 px wide on load, so the first reveal had
    // nothing to scroll and the active tab stayed off screen on a phone.
    let width = el.clientWidth
    const onResize = () => {
      if (el.clientWidth !== width) {
        width = el.clientWidth
        revealActive()
      } else update()
    }
    const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(onResize) : undefined
    const observeTabs = () => {
      if (!ro) return
      ro.disconnect()
      ro.observe(el)
      for (const tab of Array.from(el.children)) ro.observe(tab)
    }
    observeTabs()
    // Shown after mounting hidden (a `SettleGroup` releasing its children, a
    // panel opening): the resize observer reports the new width only at the
    // next frame, and a reader that measures in between (a layout check, an
    // assistive tool) saw the hidden state, "no hidden tabs", on a strip that
    // overflowed with no fade over the cut tab. An ancestor that changes its
    // `hidden`, class or style is what shows the strip, so the strip measures
    // again at once (a microtask, before any other task runs).
    const shown =
      typeof MutationObserver === 'function'
        ? new MutationObserver(() => {
            if (el.clientWidth !== width) {
              width = el.clientWidth
              revealActive()
            }
            update()
          })
        : undefined
    for (let a = el.parentElement; a; a = a.parentElement) {
      shown?.observe(a, { attributes: true, attributeFilter: ['hidden', 'class', 'style'] })
    }
    const mo =
      typeof MutationObserver === 'function'
        ? new MutationObserver((records) => {
            if (records.some((r) => r.type === 'childList' && r.target === el)) observeTabs()
            revealActive()
          })
        : undefined
    mo?.observe(el, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['data-state', 'aria-current'],
    })
    return () => {
      delete el.dataset.tabStrip
      el.removeEventListener('scroll', update)
      ro?.disconnect()
      shown?.disconnect()
      mo?.disconnect()
    }
  }, [ref, attachKey])
}

/**
 * The count shown in a tab ("Findings 12"). One look everywhere: a quiet pill
 * that follows the tab's own state. `tone="danger"` turns it red only while
 * the value is a positive number, the same rule as MetricStrip: a zero is good
 * news and stays neutral. Pass a string (e.g. "…") while loading; null/undefined
 * renders nothing. `pending` draws an empty pill of a one-digit count's width
 * while the count loads, so the tabs after it do not move when it arrives.
 */
export function TabsCount({
  value,
  pending = false,
  tone = 'default',
  className,
}: {
  value: number | string | null | undefined
  pending?: boolean
  tone?: 'default' | 'danger'
  className?: string
}) {
  if (pending)
    return (
      <span
        data-slot="tabs-count"
        data-pending=""
        aria-hidden
        className={cn(
          'inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-muted px-1.5 text-cap leading-none tabular-nums',
          className
        )}
      >
        <span className="invisible">0</span>
      </span>
    )
  if (value == null) return null
  const alarming = tone === 'danger' && typeof value === 'number' && value > 0
  return (
    <span
      data-slot="tabs-count"
      className={cn(
        'inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-muted px-1.5 text-xs font-medium leading-none tabular-nums text-muted-foreground', // design-ok: moved unchanged from tabs.tsx (TabsCount look)
        alarming && 'bg-destructive/10 text-destructive',
        className
      )}
    >
      {typeof value === 'number' ? formatNumber(value) : value}
    </span>
  )
}
