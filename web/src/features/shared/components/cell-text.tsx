import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { breakAtSeparators } from './break-text'

export interface CellTextProps {
  /** The value. A string or number is also its full text (the title). */
  children: ReactNode
  /** The full text when `children` is not plain text. */
  title?: string
  /** `auto` for stored or untrusted text (a name, an address). */
  dir?: 'auto'
  className?: string
}

/** The plain text of a value, when it has one. */
export function plainText(value: ReactNode): string | undefined {
  if (typeof value === 'string') return value.trim() || undefined
  if (typeof value === 'number') return String(value)
  return undefined
}

/**
 * A value in a table cell that is not the row's name (a description, an
 * owner, an e-mail, a list of scopes, a duration). Only a name may end in an
 * ellipsis on one line (docs/ui-style-contract.md, "cut meaning"): any other
 * value wraps, and the row grows. Past two lines the value ends in an
 * ellipsis with its full text as the title, so a very long one never makes a
 * row taller than two lines and is never lost. Plain text wraps at its
 * separators too, so an e-mail or a host name never breaks inside a word.
 */
export function CellText({ children, title, dir, className }: CellTextProps) {
  const full = title ?? plainText(children)
  return (
    <span
      data-slot="cell-text"
      // Cut after two lines on purpose: the full text is the title.
      data-cut-tooltip=""
      title={full}
      dir={dir}
      className={cn('line-clamp-2 min-w-0 break-words whitespace-normal', className)}
    >
      {typeof children === 'string' ? breakAtSeparators(children) : children}
    </span>
  )
}
