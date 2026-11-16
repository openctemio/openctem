'use client'

import { useEffect } from 'react'

/**
 * Keeps the document's `scroll-padding-top` equal to the top of the page
 * scroller `el` (below the app header and any shell banner) while the scroller is
 * mounted.
 *
 * On a client navigation the router scrolls the new page into view only when
 * the page's top is outside the "usable viewport", which it measures against
 * the window, less the root element's `scroll-padding-top`. The shell's page
 * scroller starts below the app header, so without this a page scrolled by
 * less than the header's height (or a list scrolled to its short end) kept
 * that offset on the next page: the title stayed under the header. With the
 * padding, any offset counts as out of view and the new page starts at its top.
 * A hash link and a history back/forward keep the router's own handling.
 */
export function usePageTopScrollPadding(el: HTMLElement | null) {
  useEffect(() => {
    if (!el) return
    const root = document.documentElement
    const apply = () => {
      root.style.scrollPaddingTop = `${Math.max(0, Math.floor(el.getBoundingClientRect().top))}px`
    }
    apply()
    // The scroller is the flex remainder under the header and banners, so a
    // banner that appears or leaves resizes it and moves its top.
    const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(apply)
    ro?.observe(el)
    return () => {
      ro?.disconnect()
      root.style.removeProperty('scroll-padding-top')
    }
  }, [el])
}
