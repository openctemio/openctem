'use client'

import * as React from 'react'

import { cn } from '@/lib/utils'
import { useSurfaceAutoFocus } from '@/components/ui/touch-focus'

/**
 * A text field. Inside a floating surface on a touch screen its `autoFocus`
 * is dropped, so the keyboard opens only when the user taps it
 * (`touch-focus.ts`).
 */
function Input({ className, type, autoFocus, ...props }: React.ComponentProps<'input'>) {
  const focusOnMount = useSurfaceAutoFocus(autoFocus)
  return (
    <input
      type={type}
      autoFocus={focusOnMount}
      data-slot="input"
      className={cn(
        'file:text-foreground placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground dark:bg-input/30 border-input flex h-control-field max-md:h-control-touch w-full min-w-0 rounded-md border bg-transparent px-3 py-1 text-base shadow-xs transition-[color,box-shadow] outline-none file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-body file:font-medium disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-body', // design-ok: text-base (16px) below 768px keeps phones from zooming into the field on focus
        // A placeholder longer than the field ends in an ellipsis instead of
        // being cut mid-word (a search field on a phone).
        'text-ellipsis',
        'focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]',
        'aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive',
        className
      )}
      {...props}
    />
  )
}

export { Input }
