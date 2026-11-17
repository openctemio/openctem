'use client'

/**
 * A short, single choice among two to four options: compact segments in one
 * row (stacked on a phone), the chosen option's hint on one line below
 * instead of a paragraph per option. A radio group for assistive technology
 * (arrow keys move the choice). A disabled option's reason is shown under
 * the group and as its title.
 */

import * as React from 'react'
import * as RadioGroupPrimitive from '@radix-ui/react-radio-group'

import { cn } from '@/lib/utils'

export interface ChoiceOption<V extends string> {
  value: V
  label: string
  /** One line on what the option does, shown under the group when chosen. */
  hint?: string
  disabled?: boolean
  /** Why the option is disabled (title and screen-reader description). */
  disabledReason?: string
}

interface ChoiceGroupProps<V extends string> {
  /** The group's accessible name (a visible label is the caller's). */
  label: string
  value: V
  options: readonly ChoiceOption<V>[]
  onValueChange: (value: V) => void
  className?: string
  'data-testid'?: string
}

export function ChoiceGroup<V extends string>({
  label,
  value,
  options,
  onValueChange,
  className,
  'data-testid': testId,
}: ChoiceGroupProps<V>) {
  const id = React.useId()
  const chosen = options.find((o) => o.value === value)
  const note = options.find((o) => o.disabled && o.disabledReason)
  return (
    <div className={cn('min-w-0 space-y-1.5', className)} data-testid={testId}>
      <RadioGroupPrimitive.Root
        value={value}
        onValueChange={(v) => onValueChange(v as V)}
        aria-label={label}
        aria-describedby={chosen?.hint ? `${id}-hint` : undefined}
        className="grid min-w-0 gap-0.5 rounded-lg border bg-muted p-0.5 sm:auto-cols-fr sm:grid-flow-col"
      >
        {options.map((o) => (
          <RadioGroupPrimitive.Item
            key={o.value}
            value={o.value}
            disabled={o.disabled}
            title={o.disabled ? o.disabledReason : o.hint}
            aria-describedby={o.disabled && o.disabledReason ? `${id}-why` : undefined}
            className={cn(
              // One line in a 32 track from `sm` (26 px segments); stacked rows of 36 on a phone.
              'min-h-9 min-w-0 rounded-md px-3 text-center text-dense font-medium text-muted-foreground transition-colors outline-none sm:h-control-seg sm:min-h-0 sm:truncate',
              'hover:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50',
              'data-[state=checked]:bg-background data-[state=checked]:text-foreground data-[state=checked]:shadow-xs',
              'disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:text-muted-foreground'
            )}
          >
            {o.label}
          </RadioGroupPrimitive.Item>
        ))}
      </RadioGroupPrimitive.Root>
      {chosen?.hint && (
        <p id={`${id}-hint`} className="text-cap text-muted-foreground" aria-live="polite">
          {chosen.hint}
        </p>
      )}
      {note && (
        <p id={`${id}-why`} className="text-cap text-muted-foreground">
          {note.disabledReason}
        </p>
      )}
    </div>
  )
}
