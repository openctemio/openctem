'use client'

import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

/**
 * Toggle chip (aria-pressed) for picking items of a short list (zones,
 * tools): the look of the install flow's tool chips, shared by the sensor
 * dialogs.
 */
export function ToggleChip({
  pressed,
  onToggle,
  disabled,
  children,
}: {
  pressed: boolean
  onToggle: () => void
  disabled?: boolean
  children: ReactNode
}) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      disabled={disabled}
      onClick={onToggle}
      className={cn(
        'rounded-full border px-3 py-1 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60',
        pressed
          ? 'border-primary bg-primary text-primary-foreground'
          : 'bg-background text-muted-foreground hover:bg-accent'
      )}
    >
      {children}
    </button>
  )
}
