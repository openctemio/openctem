import type * as React from 'react'
import { ExternalLink } from 'lucide-react'

// TODO(RFC-040 P0-B): replace with the shared `safeHref` / `SafeExternalLink`
// once that PR merges (RFC-040, openctemio/openctem#870). This is the
// minimal local guard until then; keep its rules no looser than these.

/**
 * An href for a scanner-supplied URL, or null when it must not be a link:
 * only absolute http(s) URLs, no embedded credentials, no control or
 * whitespace characters. Everything else (javascript:, data:, relative
 * paths, "//host") is refused rather than repaired.
 */
export function safeExternalHref(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const s = raw.trim()
  if (!s || /[\u0000-\u001f\u007f\s]/.test(s)) return null
  if (!/^https?:\/\//i.test(s)) return null
  let u: URL
  try {
    u = new URL(s)
  } catch {
    return null
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  if (u.username || u.password) return null
  return u.href
}

/**
 * A scanner-supplied URL: a link that opens in a new tab without referrer or
 * opener when it passes `safeExternalHref`, plain text otherwise.
 */
export function SafeExternalLink({
  url,
  className,
  children,
}: {
  url: string
  className?: string
  /** Link text; the URL itself when absent. */
  children?: React.ReactNode
}) {
  const href = safeExternalHref(url)
  if (!href) return <span className={className}>{url}</span>
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer nofollow"
      referrerPolicy="no-referrer"
      onClick={(e) => e.stopPropagation()}
      className={`inline-flex min-w-0 items-center gap-1 break-all hover:underline ${className ?? ''}`}
    >
      <span className="min-w-0 break-all">{children ?? url}</span>
      <ExternalLink className="h-3 w-3 shrink-0" aria-hidden="true" />
    </a>
  )
}
