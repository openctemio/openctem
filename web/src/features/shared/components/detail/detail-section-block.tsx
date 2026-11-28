'use client'

/**
 * One titled block of a detail page's tab panel, and the fold inside it.
 *
 *   <DetailSectionList>
 *     <DetailSectionBlock title="Fix" aside={<TextLink …>Remediation plan</TextLink>}>…</DetailSectionBlock>
 *     <DetailSectionBlock title="Tool evidence" count={2} actions={<Button …/>}>…</DetailSectionBlock>
 *   </DetailSectionList>
 *
 * No cards: the list draws one rule between blocks and owns the space
 * around it, so a block that renders nothing leaves no gap and no double
 * rule. A block is a `section` named by its heading (`h2`: the page title is
 * the `h1`). The title row is also the title block of a table or list that
 * follows it: name, count, then the controls at the end.
 *
 * `DetailFold` is the "Show output" / "How this was scored" line: a native
 * `details`, closed until asked for, with a muted note beside its name.
 */

import * as React from 'react'
import { ChevronRight } from 'lucide-react'

import { Counter } from '@/components/ui/counter'
import { cn } from '@/lib/utils'

export function DetailSectionList({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="detail-section-list"
      className={cn(
        'flex min-w-0 flex-col',
        '[&>*]:border-t [&>*]:border-border-subtle [&>*]:py-6',
        '[&>*:first-child]:border-t-0 [&>*:first-child]:pt-0 [&>*:last-child]:pb-0',
        className
      )}
      {...props}
    />
  )
}

export interface DetailSectionBlockProps {
  title: string
  /** How many things the block lists. */
  count?: number
  /** A mark right after the title (the AI provenance mark, a state chip). */
  mark?: React.ReactNode
  /** Controls at the end of the title row (Add, Edit, a link to more). */
  actions?: React.ReactNode
  children?: React.ReactNode
  /** For a link that scrolls to the block. */
  id?: string
  className?: string
}

export function DetailSectionBlock({
  title,
  count,
  mark,
  actions,
  children,
  id,
  className,
}: DetailSectionBlockProps) {
  const headingId = React.useId()
  return (
    <section
      id={id}
      data-slot="detail-section-block"
      aria-labelledby={headingId}
      className={cn('min-w-0', className)}
    >
      <div
        data-slot="detail-section-title"
        // At most 40rem: on a wide page the controls stay near their title.
        className="flex min-h-control max-w-[40rem] flex-wrap items-center justify-between gap-x-3 gap-y-1"
      >
        <div className="flex max-w-full min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <h2 id={headingId} className="min-w-0 text-section break-words">
            {title}
          </h2>
          {count !== undefined && <Counter value={count} />}
          {mark}
        </div>
        {actions && (
          <div
            data-slot="detail-section-actions"
            className="ms-auto flex max-w-full min-w-0 flex-wrap items-center justify-end gap-2"
          >
            {actions}
          </div>
        )}
      </div>
      {children !== undefined && children !== null && children !== false && (
        <div data-slot="detail-section-body" className="mt-3 min-w-0">
          {children}
        </div>
      )}
    </section>
  )
}

export interface DetailFoldProps {
  /** The fold's name, e.g. "How this was scored". */
  label: string
  /** A short note beside the name ("score 13.5 of 15", "9 fields"). */
  note?: React.ReactNode
  defaultOpen?: boolean
  children: React.ReactNode
  className?: string
}

export function DetailFold({ label, note, defaultOpen, children, className }: DetailFoldProps) {
  return (
    <details data-slot="detail-fold" open={defaultOpen} className={cn('group min-w-0', className)}>
      <summary className="flex min-h-control cursor-pointer list-none items-center gap-2 rounded-sm text-body select-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none max-md:min-h-touch-target [&::-webkit-details-marker]:hidden">
        <ChevronRight
          className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-90 rtl:rotate-180"
          aria-hidden
        />
        <span className="font-semibold">{label}</span>
        {note && <span className="min-w-0 text-muted-foreground">{note}</span>}
      </summary>
      <div data-slot="detail-fold-body" className="mt-2 min-w-0 ps-6">
        {children}
      </div>
    </details>
  )
}
