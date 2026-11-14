'use client'

import * as React from 'react'
import { ExternalLink } from 'lucide-react'

import Link from '@/components/link'
import { SafeExternalLink } from '@/components/safe-external-link'
import { useTranslation } from '@/context/i18n-provider'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

/**
 * The one text link (web/docs/ui-style-contract.md, "Links").
 *
 * - `inline`: a link inside running text (a sentence, a hint, a callout, an
 *   empty-state line). Underlined at rest, the underline at 45% of the text
 *   colour, 3px under the baseline.
 * - `nav` (default): a standalone link (a cell or row name, an id, a
 *   breadcrumb, a card title, "View all", a count). Plain at rest, underlined
 *   on hover and keyboard focus.
 *
 * Buttons, chips and tabs are never links of this kind. `external` opens the
 * URL in a new tab through SafeExternalLink (http/https only, noopener) and
 * draws the external icon; an internal `href` goes through safeHref too, so a
 * data-driven path can never become a `javascript:` URL (RFC-040).
 */
export const TEXT_LINK_CLASS = {
  inline:
    'text-signal-text underline decoration-signal-text/45 underline-offset-3 hover:decoration-current focus-visible:decoration-current',
  nav: 'underline-offset-3 hover:underline focus-visible:underline',
} as const

export interface TextLinkProps extends Omit<
  React.AnchorHTMLAttributes<HTMLAnchorElement>,
  'href' | 'target' | 'rel'
> {
  href: string | null | undefined
  variant?: keyof typeof TEXT_LINK_CLASS
  /** Another site: a new tab, the external icon, and only http/https URLs. */
  external?: boolean
}

export function TextLink({
  href,
  variant = 'nav',
  external = false,
  className,
  children,
  ...rest
}: TextLinkProps) {
  const { t } = useTranslation()
  const cls = cn(TEXT_LINK_CLASS[variant], className)

  if (external) {
    return (
      <SafeExternalLink
        {...rest}
        href={href}
        className={cn('inline-flex items-baseline gap-1', cls)}
      >
        {children}
        <ExternalLink className="size-3.5 shrink-0 self-center" aria-hidden />
        <span className="sr-only">{t('common.link.opensInNewTab', '(opens in a new tab)')}</span>
      </SafeExternalLink>
    )
  }

  const safe = safeHref(href)
  if (!safe) {
    return (
      <span className={className} data-unsafe-href="">
        {children}
      </span>
    )
  }
  return (
    <Link {...rest} href={safe} className={cls}>
      {children}
    </Link>
  )
}
