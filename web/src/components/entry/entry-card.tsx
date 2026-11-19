import type { ComponentProps, ReactNode } from 'react'
import { CircleAlert, CircleCheck, Info, TriangleAlert, type LucideIcon } from 'lucide-react'

import { STATUS_TONE_BG } from '@/lib/status-colors'
import { cn } from '@/lib/utils'

/**
 * The parts of an entry page (see EntryFrame): one card, its title, the
 * banner that carries a notice or an error, the divider between ways to
 * continue, the row of actions and the centred secondary lines. They hold
 * layout and type only; fields and buttons are the kit's, at the entry
 * control height.
 */

/** The card: a bordered surface from 640px, the bare screen column below. */
export function EntryCard({ className, ...props }: ComponentProps<'section'>) {
  return (
    <section
      data-slot="card"
      data-entry="card"
      className={cn(
        'text-foreground flex w-full min-w-0 flex-col gap-3.5 sm:bg-card sm:rounded-lg sm:border sm:p-6',
        className
      )}
      {...props}
    />
  )
}

export interface EntryHeaderProps {
  title: ReactNode
  description?: ReactNode
  /** The page's own title is an h1; a second card or a step under it an h2. */
  level?: 1 | 2
  className?: string
}

/** Title and one line under it. */
export function EntryHeader({ title, description, level = 1, className }: EntryHeaderProps) {
  const Heading = level === 1 ? 'h1' : 'h2'
  return (
    <div data-slot="entry-header" className={cn('flex flex-col gap-1', className)}>
      <Heading className={level === 1 ? 'text-page' : 'text-section'}>{title}</Heading>
      {description ? (
        <div data-slot="entry-description" className="text-body text-muted-foreground">
          {description}
        </div>
      ) : null}
    </div>
  )
}

export type EntryTone = 'info' | 'ok' | 'warn' | 'danger'

// Tints from the one status colour source; danger is the shared danger tone.
const TONES: Record<EntryTone, { cls: string; icon: LucideIcon }> = {
  info: { cls: STATUS_TONE_BG.progress, icon: Info },
  ok: { cls: STATUS_TONE_BG.resolved, icon: CircleCheck },
  warn: { cls: STATUS_TONE_BG.accepted, icon: TriangleAlert },
  danger: { cls: 'bg-tone-danger-bg', icon: CircleAlert },
}

export interface EntryBannerProps extends Omit<ComponentProps<'div'>, 'title'> {
  tone?: EntryTone
  title?: ReactNode
  /**
   * `alert` interrupts (a failure the visitor must act on); `status` is read
   * when the screen reader is idle (a notice, a warning, a success). Default:
   * `alert` for the danger tone only.
   */
  role?: 'alert' | 'status'
}

/** A notice, a success or an error above the fields, in ink on a tint. */
export function EntryBanner({
  tone = 'info',
  title,
  role,
  className,
  children,
  ...props
}: EntryBannerProps) {
  const { cls, icon: Icon } = TONES[tone]
  return (
    <div
      data-slot="entry-banner"
      data-tone={tone}
      role={role ?? (tone === 'danger' ? 'alert' : 'status')}
      className={cn(
        'text-dense text-foreground flex items-start gap-2.5 rounded-lg border px-3 py-2.5',
        cls,
        className
      )}
      {...props}
    >
      <Icon aria-hidden className="mt-0.5 size-4 shrink-0" />
      <div className="flex min-w-0 flex-col gap-1 break-words">
        {title ? <p className="font-medium">{title}</p> : null}
        {children}
      </div>
    </div>
  )
}

/** "Or continue with": a rule on each side of a short label. */
export function EntryDivider({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      data-slot="entry-divider"
      className={cn(
        'text-cap text-muted-foreground before:bg-border after:bg-border flex items-center gap-2 before:h-px before:flex-1 after:h-px after:flex-1',
        className
      )}
    >
      {children}
    </div>
  )
}

/** A centred secondary line under the form ("Don't have an account? Sign up"). */
export function EntryLine({ className, ...props }: ComponentProps<'p'>) {
  return (
    <p
      data-slot="entry-line"
      className={cn('text-dense text-center empty:hidden', className)}
      {...props}
    />
  )
}

/** Small print inside the card (the legal notice, a hint about the next step). */
export function EntryNote({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="entry-note"
      className={cn('text-cap text-muted-foreground empty:hidden', className)}
      {...props}
    />
  )
}

/**
 * The card's actions: stacked and full width by default (one primary action,
 * then the ways back); `row` for a pair that reads as a choice (Decline,
 * Accept), which wraps on a narrow screen.
 */
export function EntryActions({
  layout = 'stack',
  className,
  ...props
}: ComponentProps<'div'> & { layout?: 'stack' | 'row' }) {
  return (
    <div
      data-slot="entry-actions"
      className={cn(
        layout === 'stack'
          ? 'flex flex-col gap-2 [&>*]:w-full'
          : 'flex flex-wrap justify-end gap-2 max-sm:[&>*]:flex-1',
        className
      )}
      {...props}
    />
  )
}
