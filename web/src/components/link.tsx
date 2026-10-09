'use client'

import { useState, type ComponentProps } from 'react'
import NextLink from 'next/link'

type LinkProps = ComponentProps<typeof NextLink>

/**
 * The app's link: `next/link` that prefetches on intent (pointer, focus or
 * touch) instead of as soon as it is in view.
 *
 * Next prefetches every link in the viewport, and each prefetch costs two
 * route requests (the route tree, then its segment data). A page with a
 * dozen links (the dashboard's CTEM loop, a breadcrumb, a toolbar) sent two
 * dozen requests on load for pages the user mostly never opens (research/81).
 * Arming the prefetch on intent still gives the route the 100-300 ms between
 * pointing and clicking, the pattern Next recommends for many links.
 *
 * An explicit `prefetch` prop wins (`prefetch={false}` never prefetches,
 * `prefetch` / `prefetch={true}` prefetches the full route at once).
 * `src/lib/__tests__/request-hygiene-guard.test.ts` keeps `next/link`
 * imports to this file (and `useLinkStatus`).
 */
export default function Link({
  prefetch,
  onMouseEnter,
  onFocus,
  onTouchStart,
  ...props
}: LinkProps) {
  const [intent, setIntent] = useState(false)
  return (
    <NextLink
      {...props}
      prefetch={prefetch !== undefined ? prefetch : intent ? null : false}
      onMouseEnter={(e) => {
        setIntent(true)
        onMouseEnter?.(e)
      }}
      onFocus={(e) => {
        setIntent(true)
        onFocus?.(e)
      }}
      onTouchStart={(e) => {
        setIntent(true)
        onTouchStart?.(e)
      }}
    />
  )
}
