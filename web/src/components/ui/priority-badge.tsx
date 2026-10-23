import { cn } from '@/lib/utils'
import { PRIORITY_BOX_CLASS, type PriorityClass } from '@/lib/priority-colors'

export interface PriorityBadgeProps {
  /** The class to show: P0 (immediate) to P3 (track). */
  priorityClass: PriorityClass
  className?: string
}

/**
 * A priority class as a filled box (P0 strongest). The one rendering of a
 * class: lists, drawers, dashboards and the finding detail all use it. The
 * text "P0".."P3" is always present, so colour is never the only cue.
 */
export function PriorityBadge({ priorityClass, className }: PriorityBadgeProps) {
  const box = PRIORITY_BOX_CLASS[priorityClass] ?? PRIORITY_BOX_CLASS.P3
  return (
    <span
      data-slot="priority-badge"
      data-priority={priorityClass}
      className={cn(
        'inline-flex w-fit shrink-0 items-center justify-center whitespace-nowrap rounded-sm border px-1.5 py-0.5 font-mono text-xs font-bold leading-none',
        box,
        className
      )}
    >
      {priorityClass}
    </span>
  )
}
