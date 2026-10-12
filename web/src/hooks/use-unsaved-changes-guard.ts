'use client'

import * as React from 'react'

/**
 * Warns before leaving a page with unsaved changes.
 *
 * - Closing or reloading the tab: the browser's own beforeunload prompt.
 * - In-app links: a click on a same-origin link is held and `onBlocked`
 *   receives its URL, so the page can ask and then navigate.
 *
 * Links opened in a new tab or window, downloads and hash links pass.
 */
export function useUnsavedChangesGuard(dirty: boolean, onBlocked: (href: string) => void) {
  const onBlockedRef = React.useRef(onBlocked)
  React.useEffect(() => {
    onBlockedRef.current = onBlocked
  }, [onBlocked])

  React.useEffect(() => {
    if (!dirty) return
    const beforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      // Some browsers still need a return value to show the prompt.
      e.returnValue = ''
    }
    const onClick = (e: MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0) return
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
      const a = (e.target as Element | null)?.closest?.('a[href]') as HTMLAnchorElement | null
      if (!a || a.target === '_blank' || a.hasAttribute('download')) return
      if (a.dataset.skipUnsavedGuard !== undefined) return
      const url = new URL(a.href, window.location.href)
      if (url.origin !== window.location.origin) return
      if (url.pathname === window.location.pathname && url.search === window.location.search) return
      e.preventDefault()
      e.stopPropagation()
      onBlockedRef.current(url.pathname + url.search + url.hash)
    }
    window.addEventListener('beforeunload', beforeUnload)
    document.addEventListener('click', onClick, true)
    return () => {
      window.removeEventListener('beforeunload', beforeUnload)
      document.removeEventListener('click', onClick, true)
    }
  }, [dirty])
}
