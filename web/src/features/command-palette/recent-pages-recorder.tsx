'use client'

import { useEffect } from 'react'
import { usePathname } from 'next/navigation'
import { recordRecentPage } from './recent-pages'

/**
 * Notes each page the person opens for the command palette's "Recent" group
 * (recent-pages.ts). Renders nothing; kept apart from the palette, which
 * loads only when it first opens.
 */
export function RecentPagesRecorder() {
  const pathname = usePathname()
  useEffect(() => {
    recordRecentPage(pathname)
  }, [pathname])
  return null
}
