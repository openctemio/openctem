'use client'

/** A searchable IANA timezone picker (the zones the browser knows). */

import { useId, useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Check, ChevronDownIcon } from 'lucide-react'
import { SELECT_TRIGGER_CLASS } from '@/components/ui/select'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { cn } from '@/lib/utils'
import { timeZoneOptions } from '../lib/zoned-time'

interface TimezoneSelectProps {
  id?: string
  value: string
  onChange: (zone: string) => void
  disabled?: boolean
  /** Ids of the help text that describes the picker. */
  'aria-describedby'?: string
}

export function TimezoneSelect({
  id,
  value,
  onChange,
  disabled,
  'aria-describedby': describedBy,
}: TimezoneSelectProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const listId = useId()
  const zones = useMemo(() => timeZoneOptions(value), [value])
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        {/* The select field's look (border, height, 16px text on a phone,
            chevron), so it matches the other fields of the form. */}
        <button
          id={id}
          type="button"
          role="combobox"
          data-slot="select-trigger"
          data-size="default"
          aria-expanded={open}
          aria-controls={listId}
          aria-describedby={describedBy}
          disabled={disabled}
          className={cn(SELECT_TRIGGER_CLASS, 'w-full')}
        >
          <span className="min-w-0 truncate">{value}</span>
          <ChevronDownIcon className="size-4 opacity-50" aria-hidden />
        </button>
      </PopoverTrigger>
      <PopoverContent id={listId} className="w-[--radix-popover-trigger-width] min-w-64 p-0">
        <Command>
          <CommandInput placeholder={t('scans.timezone.search')} />
          <CommandList className="max-h-64">
            <CommandEmpty>{t('scans.timezone.none')}</CommandEmpty>
            <CommandGroup>
              {zones.map((zone) => (
                <CommandItem
                  key={zone}
                  value={zone}
                  onSelect={() => {
                    onChange(zone)
                    setOpen(false)
                  }}
                >
                  <Check
                    className={cn('me-2 h-4 w-4', zone === value ? 'opacity-100' : 'opacity-0')}
                    aria-hidden
                  />
                  {zone}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
