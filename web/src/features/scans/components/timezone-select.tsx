'use client'

/** A searchable IANA timezone picker (the zones the browser knows). */

import { useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Check, ChevronsUpDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
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
}

export function TimezoneSelect({ id, value, onChange }: TimezoneSelectProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const zones = useMemo(() => timeZoneOptions(value), [value])
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="w-full justify-between font-normal"
        >
          <span className="truncate">{value}</span>
          <ChevronsUpDown className="ms-2 h-4 w-4 shrink-0 opacity-50" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[--radix-popover-trigger-width] min-w-64 p-0" align="start">
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
