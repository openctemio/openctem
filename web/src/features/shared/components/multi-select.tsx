'use client'

/**
 * Pick several values from a list: a combobox button that opens a
 * searchable list with a check per item, and the picked values as
 * removable chips under it. Keyboard: the button opens the list, arrows
 * move, Enter toggles, Escape closes; each chip's remove button is
 * focusable. Values unknown to `options` (an id the caller cannot read)
 * still show, with `unknownLabel`.
 */

import * as React from 'react'
import { Check, ChevronsUpDown, X } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { cn } from '@/lib/utils'

export interface MultiSelectOption {
  value: string
  label: string
}

export interface MultiSelectProps {
  id?: string
  options: MultiSelectOption[]
  value: string[]
  onChange: (value: string[]) => void
  placeholder?: string
  searchPlaceholder?: string
  emptyText?: string
  /** Label of a picked value that is not in `options`. */
  unknownLabel?: (value: string) => string
  /** Accessible name of a chip's remove button. */
  removeLabel?: (label: string) => string
  /** The button text once something is picked. */
  selectedLabel?: (count: number) => string
  disabled?: boolean
  loading?: boolean
  className?: string
  'aria-describedby'?: string
}

export function MultiSelect({
  id,
  options,
  value,
  onChange,
  placeholder = 'Select…',
  searchPlaceholder = 'Search…',
  emptyText = 'Nothing found.',
  unknownLabel = (v) => v,
  removeLabel = (l) => `Remove ${l}`,
  selectedLabel = (n) => `${n} selected`,
  disabled,
  loading,
  className,
  'aria-describedby': describedBy,
}: MultiSelectProps) {
  const [open, setOpen] = React.useState(false)
  const labels = React.useMemo(() => new Map(options.map((o) => [o.value, o.label])), [options])
  const picked = React.useMemo(() => new Set(value), [value])
  const toggle = (v: string) =>
    onChange(picked.has(v) ? value.filter((x) => x !== v) : [...value, v])

  return (
    <div className={cn('space-y-1.5', className)}>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            id={id}
            type="button"
            variant="outline"
            role="combobox"
            aria-expanded={open}
            aria-describedby={describedBy}
            disabled={disabled}
            className="w-full justify-between font-normal"
          >
            <span className={cn('truncate', value.length === 0 && 'text-muted-foreground')}>
              {value.length === 0 ? placeholder : selectedLabel(value.length)}
            </span>
            <ChevronsUpDown className="ms-2 h-4 w-4 shrink-0 opacity-50" aria-hidden />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[--radix-popover-trigger-width] min-w-56 p-0" align="start">
          <Command
            filter={(itemValue, search) =>
              itemValue.toLowerCase().includes(search.toLowerCase()) ? 1 : 0
            }
          >
            <CommandInput placeholder={searchPlaceholder} />
            <CommandList>
              <CommandEmpty>{loading ? '…' : emptyText}</CommandEmpty>
              <CommandGroup>
                {options.map((o) => (
                  <CommandItem
                    key={o.value}
                    value={`${o.label} ${o.value}`}
                    onSelect={() => toggle(o.value)}
                    aria-selected={picked.has(o.value)}
                  >
                    <Check
                      className={cn(
                        'me-2 h-4 w-4',
                        picked.has(o.value) ? 'opacity-100' : 'opacity-0'
                      )}
                      aria-hidden
                    />
                    <span className="truncate">{o.label}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {value.map((v) => {
            const label = labels.get(v) ?? unknownLabel(v)
            return (
              <Badge key={v} variant="secondary" className="gap-1 pe-1 font-normal">
                <span className="max-w-48 truncate">{label}</span>
                <button
                  type="button"
                  className="rounded-sm p-0.5 hover:bg-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  aria-label={removeLabel(label)}
                  disabled={disabled}
                  onClick={() => onChange(value.filter((x) => x !== v))}
                >
                  <X className="h-3 w-3" aria-hidden />
                </button>
              </Badge>
            )
          })}
        </div>
      )}
    </div>
  )
}
