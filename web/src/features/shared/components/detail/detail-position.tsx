'use client'

/**
 * "‹ 2 of 27 ›": where a record sits in the list it was opened from, with the
 * previous and next record. The count links back to that list (its name is
 * the link's accessible name and tooltip). The page that owns the list
 * context builds the links and the key handling (j / k); this draws them.
 */

import { ChevronLeft, ChevronRight } from 'lucide-react'

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { TextLink } from '@/components/ui/text-link'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

export interface DetailPositionProps {
  /** "{n} of {total}", already translated (1-based place in the list). */
  label: string
  /** Back to the list, with its filters. */
  listHref?: string
  /** The list's name: the count link's tooltip and accessible description. */
  listLabel?: string
  prevHref?: string
  nextHref?: string
  /** Accessible names, with the key in them, e.g. "Previous finding (k)". */
  prevLabel: string
  nextLabel: string
  className?: string
}

function Step({
  href,
  label,
  children,
}: {
  href?: string
  label: string
  children: React.ReactNode
}) {
  return (
    <Button
      asChild={!!href}
      variant="ghost"
      size="icon"
      disabled={!href}
      aria-label={label}
      title={label}
    >
      {href ? <Link href={safeHref(href) ?? '#'}>{children}</Link> : children}
    </Button>
  )
}

export function DetailPosition({
  label,
  listHref,
  listLabel,
  prevHref,
  nextHref,
  prevLabel,
  nextLabel,
  className,
}: DetailPositionProps) {
  return (
    <div data-slot="detail-position" className={cn('flex shrink-0 items-center gap-1', className)}>
      <Step href={safeHref(prevHref)} label={prevLabel}>
        <ChevronLeft className="rtl:rotate-180" aria-hidden />
      </Step>
      <span className="px-1 text-dense tabular-nums whitespace-nowrap" aria-live="polite">
        {listHref ? (
          <TextLink href={safeHref(listHref)} title={listLabel} className="text-signal-text">
            {label}
          </TextLink>
        ) : (
          <span className="text-muted-foreground">{label}</span>
        )}
      </span>
      <Step href={safeHref(nextHref)} label={nextLabel}>
        <ChevronRight className="rtl:rotate-180" aria-hidden />
      </Step>
    </div>
  )
}
