'use client'

/**
 * The asset group's business unit: chips for the organization's own units
 * (GET /business-units), never a built-in list, plus free text. With no unit
 * yet it says so and links to where units are created.
 */

import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { useBusinessUnits } from '@/features/business-units/api/use-business-units'
import { cn } from '@/lib/utils'

interface BusinessUnitFieldProps {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
  /** How many unit chips to show (the rest are reachable by typing). */
  max?: number
}

export function BusinessUnitField({ value, onChange, disabled, max = 8 }: BusinessUnitFieldProps) {
  const { t } = useTranslation()
  const { data, isLoading, error } = useBusinessUnits()
  const units = (data?.data ?? []).map((u) => u.name)
  const shown = units.slice(0, max)
  const isUnit = units.includes(value)

  return (
    <div className="space-y-2">
      {shown.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {shown.map((bu) => (
            <Badge
              key={bu}
              variant={value === bu ? 'default' : 'outline'}
              className={cn(
                'cursor-pointer text-xs transition-colors',
                value === bu ? '' : 'hover:bg-muted',
                disabled && 'pointer-events-none opacity-50'
              )}
              onClick={() => onChange(value === bu ? '' : bu)}
            >
              {bu}
            </Badge>
          ))}
        </div>
      ) : !isLoading && !error ? (
        <p className="text-xs text-muted-foreground">
          {t('assets.groups.bu.none', 'No business units yet.')}{' '}
          <Link href="/business-units" className="underline underline-offset-2">
            {t('assets.groups.bu.create', 'Create one')}
          </Link>
        </p>
      ) : null}
      <Input
        placeholder={t('assets.groups.bu.custom', 'Or type a business unit…')}
        value={isUnit ? '' : value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
      />
    </div>
  )
}
