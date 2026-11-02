import type { HTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

/**
 * Text that repeats or decorates a control's label: a shortcut hint ("Ctrl
 * K", "t") or an initials chip beside the name it abbreviates. A control named
 * by aria-label must contain its visible label text (WCAG 2.5.3, label in
 * name); this text is drawn by CSS (generated content, not a text node), so
 * it is neither part of the label a speech user says nor read twice.
 * Use it only inside a control that carries its own name.
 */
export function DecorativeText({
  text,
  as: Tag = 'span',
  className,
  ...rest
}: { text: string; as?: 'span' | 'kbd' | 'div' } & Omit<HTMLAttributes<HTMLElement>, 'children'>) {
  return (
    <Tag
      {...rest}
      aria-hidden
      data-text={text}
      className={cn('before:content-[attr(data-text)]', className)}
    />
  )
}
