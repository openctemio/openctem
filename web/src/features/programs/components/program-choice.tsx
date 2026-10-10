'use client'

/**
 * A choice between a few options shown as cards (icon, title, one line),
 * each a radio item: the scope source on /programs/new and the program's
 * visibility (RFC-065 §15).
 */

import type { ElementType } from 'react'
import { useId } from 'react'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { cn } from '@/lib/utils'

export interface ChoiceOption<T extends string> {
  value: T
  icon: ElementType
  title: string
  description: string
}

interface ProgramChoiceProps<T extends string> {
  label: string
  value: T
  options: ChoiceOption<T>[]
  onChange: (value: T) => void
}

export function ProgramChoice<T extends string>({
  label,
  value,
  options,
  onChange,
}: ProgramChoiceProps<T>) {
  const id = useId()
  return (
    <RadioGroup
      aria-label={label}
      value={value}
      onValueChange={(v) => onChange(v as T)}
      className="grid gap-3 sm:grid-cols-2"
    >
      {options.map((o) => {
        const Icon = o.icon
        const itemId = `${id}-${o.value}`
        return (
          <label
            key={o.value}
            htmlFor={itemId}
            className={cn(
              'flex cursor-pointer items-start gap-3 rounded-xl border p-4 transition-colors',
              value === o.value ? 'border-primary bg-primary/5' : 'hover:border-primary/50'
            )}
          >
            <RadioGroupItem value={o.value} id={itemId} className="mt-1" />
            <Icon className="text-muted-foreground mt-0.5 h-5 w-5 shrink-0" aria-hidden />
            <span className="min-w-0">
              <span className="block font-medium">{o.title}</span>
              <span className="text-muted-foreground block text-sm">{o.description}</span>
            </span>
          </label>
        )
      })}
    </RadioGroup>
  )
}
