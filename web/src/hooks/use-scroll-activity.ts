'use client'

import { useEffect, type RefObject } from 'react'

/**
 * Marks an element with `data-scrolling` while it scrolls and for `idleMs`
 * after the last scroll event. The `scrollbar-auto-hide` utility shows the
 * scrollbar thumb only while that attribute is present, so scrollbars behave
 * like overlay scrollbars without shifting the layout.
 */
export function useScrollActivity(ref: RefObject<HTMLElement | null>, idleMs = 900) {
  useEffect(() => {
    const el = ref.current
    if (!el) return
    let timer: ReturnType<typeof setTimeout> | undefined
    const onScroll = () => {
      el.setAttribute('data-scrolling', '')
      clearTimeout(timer)
      timer = setTimeout(() => el.removeAttribute('data-scrolling'), idleMs)
    }
    el.addEventListener('scroll', onScroll, { passive: true })
    return () => {
      el.removeEventListener('scroll', onScroll)
      clearTimeout(timer)
      el.removeAttribute('data-scrolling')
    }
  }, [ref, idleMs])
}
