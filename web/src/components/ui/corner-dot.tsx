import { cn } from '@/lib/utils'

/**
 * Where a state mark sits on a control: on its top-end corner, over the
 * border, out of the layout. The control's content (an icon in a square
 * button) stays centred and the control keeps its width whether the mark
 * shows or not. The control must be positioned (`Button` is `relative`).
 */
export const CORNER_MARK = 'pointer-events-none absolute -end-1 -top-1'

const TONE = {
  /** Something left to do (unsaved changes). */
  warning: 'bg-warning',
  /** Something new (unread). */
  primary: 'bg-primary',
} as const

/**
 * A dot on a control's corner: unsaved changes on the saved-views button,
 * something unread on an activity trigger. State by shape and colour, never
 * colour alone: the control's accessible name says it too, so the dot itself
 * is hidden from assistive technology. A count uses `Counter size="badge"`
 * at the same place (`CORNER_MARK`).
 */
export function CornerDot({
  tone = 'warning',
  className,
  'data-testid': testId,
}: {
  tone?: keyof typeof TONE
  /** The ring takes the colour of the surface under the control (`ring-card` on a card). */
  className?: string
  'data-testid'?: string
}) {
  return (
    <span
      aria-hidden
      data-slot="corner-dot"
      data-testid={testId}
      className={cn(
        CORNER_MARK,
        'size-2.5 rounded-full ring-2 ring-background',
        TONE[tone],
        className
      )}
    />
  )
}
