import * as React from 'react'

import { safeHref, type SafeHrefOptions } from '@/lib/safe-href'

export interface SafeExternalLinkProps extends Omit<
  React.AnchorHTMLAttributes<HTMLAnchorElement>,
  'href' | 'target' | 'rel'
> {
  /** The untrusted URL (scanner reference, asset URL, evidence URI …). */
  href: string | null | undefined
  /** Passed to {@link safeHref}; relative paths are allowed by default. */
  urlOptions?: SafeHrefOptions
  ref?: React.Ref<HTMLAnchorElement>
}

/**
 * An external link whose URL comes from data. The URL goes through
 * `safeHref` (http/https, same-origin paths; never `javascript:`, `data:`,
 * `vbscript:` or `//host`), opens in a new tab and carries
 * `rel="noopener noreferrer nofollow"`. When the URL is refused the children
 * still render, as plain text without a link, so the analyst sees the value.
 *
 * Works under Radix `asChild` (DropdownMenuItem, Button): props and ref are
 * forwarded to the anchor.
 */
export function SafeExternalLink({
  href,
  urlOptions,
  children,
  className,
  title,
  ref,
  ...rest
}: SafeExternalLinkProps) {
  const safe = safeHref(href, urlOptions)
  if (!safe) {
    return (
      <span
        className={className}
        title={title ?? 'Link not opened: the URL uses a scheme that is not allowed'}
        data-unsafe-href=""
      >
        {children}
      </span>
    )
  }
  return (
    <a
      {...rest}
      ref={ref}
      href={safe}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className={className}
      title={title}
    >
      {children}
    </a>
  )
}
