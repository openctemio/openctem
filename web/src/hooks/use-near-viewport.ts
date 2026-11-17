'use client'

import { useEffect, useState } from 'react'

/**
 * True from the first time the element with this id comes near the viewport
 * (within `rootMargin`), for good. A section low on a long page reads its data
 * only then, so the page's load sends only the reads of what is on screen. A
 * link to the section (hash, `?tab=`, settings search) scrolls it into view,
 * which counts as near. Without IntersectionObserver the answer is true at once.
 */
export function useNearViewport(id: string, rootMargin = '0px 0px 200px 0px'): boolean {
  const [near, setNear] = useState(false)
  useEffect(() => {
    if (near) return
    const el = document.getElementById(id)
    if (!el || typeof IntersectionObserver === 'undefined') {
      setNear(true)
      return
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setNear(true)
          observer.disconnect()
        }
      },
      { rootMargin }
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [id, rootMargin, near])
  return near
}
