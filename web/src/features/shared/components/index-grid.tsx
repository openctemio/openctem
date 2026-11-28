import type { ComponentProps, ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * The frame of an index page (an overview of links in groups: the settings
 * overview, a section's overview). web/docs/ui-style-contract.md, "Index
 * pages": an index uses the page's width; it is never a reading column.
 *
 * - `IndexGroups` lays the groups out one under the other, and two side by
 *   side once the content is 80rem wide (1280 px: a 1920 px screen with the
 *   sidebar), each as tall as its own links (no stretched card).
 * - `IndexLinkList` lays a group's links in as many columns as fit, at least
 *   14rem each, so a wide screen shows more links per row instead of an
 *   empty band beside three narrow columns.
 */
export function IndexGroups({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div data-slot="index-groups" className={cn('@container min-w-0', className)}>
      <div className="grid items-start gap-section @[80rem]:grid-cols-2">{children}</div>
    </div>
  )
}

export function IndexLinkList({ className, ...props }: ComponentProps<'ul'>) {
  return (
    <ul
      data-slot="index-link-list"
      className={cn(
        'grid grid-cols-[repeat(auto-fill,minmax(min(100%,14rem),1fr))] gap-x-6',
        className
      )}
      {...props}
    />
  )
}
