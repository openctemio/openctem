import type { ComponentProps } from 'react'
import { cn } from '@/lib/utils'

/**
 * The vertical rhythm of a page (research/244). Put a page's blocks (the
 * `PageHeader`, its tabs, banners, a `MetricStrip`, the list) in one
 * `PageStack` and the stack owns every gap between them:
 *
 * - 20px (`gap-page`) between any two blocks;
 * - 16px (`page-tight`) from a `PageHeader` to the tab strip right under it
 *   (route `SectionTabs` or in-page `Tabs`).
 *
 * Blocks carry no vertical margin of their own; the stack zeroes any that a
 * child still has. The gap used to live on the block below (`mt-5`), so when
 * that block rendered nothing (a banner with no windows) the next block sat
 * flush against the tabs. A block that renders `null` takes no gap here. Do
 * not wrap an optional block in an empty `<div>`: an empty element still
 * takes a gap.
 *
 * A tab panel or a component that renders several blocks wraps them in its
 * own `PageStack`; nested stacks keep the same rhythm. Inline Radix `Tabs`
 * directly inside a stack get the same 20px between the strip and the panel.
 */
export function PageStack({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="page-stack"
      className={cn(
        'flex min-w-0 flex-col gap-page',
        '[&>*]:my-0!',
        '[&>[data-slot=page-header]+[data-slot=page-tabs]]:-mt-1!',
        // In-page tabs right under the header sit as close as route tabs.
        '[&>[data-slot=page-header]+[data-slot=tabs]]:-mt-1!',
        '[&>[data-slot=tabs]]:gap-page',
        className
      )}
      {...props}
    />
  )
}
