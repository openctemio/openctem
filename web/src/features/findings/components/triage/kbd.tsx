import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * A key cap. Decorative by default (next to a button label, the button names
 * the action); the keys dialog shows it to assistive technology too.
 */
export function Kbd({
  children,
  className,
  decorative = true,
}: {
  children: ReactNode
  className?: string
  decorative?: boolean
}) {
  return (
    <kbd
      aria-hidden={decorative || undefined}
      className={cn(
        'inline-flex min-w-5 items-center justify-center rounded border border-b-2 border-current/30 px-1 font-mono text-xs leading-4 font-medium',
        className
      )}
    >
      {children}
    </kbd>
  )
}
