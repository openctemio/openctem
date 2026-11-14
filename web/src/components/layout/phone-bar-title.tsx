'use client'

import { useEffect, useId, type RefObject } from 'react'
import { create } from 'zustand'

/**
 * The phone bar's title (shell package D1): a page draws its title once, as
 * the H1 of its page header. Below 768 px the bar repeats that name (16/24
 * 600, hidden from assistive tech) only after the H1 has scrolled under the
 * bar, so the page never shows its name twice at rest.
 */

interface PhoneBarTitleState {
  /** The page header that set the title; only it may clear it. */
  owner: string | null
  title: string | null
}

const usePhoneBarTitleStore = create<PhoneBarTitleState>(() => ({ owner: null, title: null }))

/** The top bar's height (`h-12`): the H1 is gone once it is fully under it. */
const BAR_HEIGHT = 48

/** Publish `title` to the phone bar while the element in `ref` is scrolled under the bar. */
export function usePhoneBarTitle(ref: RefObject<HTMLElement | null>, title: string) {
  const owner = useId()
  useEffect(() => {
    const el = ref.current
    if (!el || typeof IntersectionObserver === 'undefined') return
    const clear = () => {
      if (usePhoneBarTitleStore.getState().owner === owner) {
        usePhoneBarTitleStore.setState({ owner: null, title: null })
      }
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry) return
        const under = !entry.isIntersecting && entry.boundingClientRect.top < BAR_HEIGHT
        if (under) usePhoneBarTitleStore.setState({ owner, title })
        else clear()
      },
      { rootMargin: `-${BAR_HEIGHT}px 0px 0px 0px` }
    )
    observer.observe(el)
    return () => {
      observer.disconnect()
      clear()
    }
  }, [ref, title, owner])
}

/** The title slot of the phone bar (renders nothing at rest and from 768 px). */
export function PhoneBarTitle() {
  const title = usePhoneBarTitleStore((s) => s.title)
  if (!title) return null
  return (
    <span
      data-slot="phone-bar-title"
      data-sticky=""
      aria-hidden
      className="text-section min-w-0 flex-1 truncate md:hidden"
    >
      {title}
    </span>
  )
}
