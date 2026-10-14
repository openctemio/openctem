'use client'

/**
 * Picks one Tenable.sc object (policy, repository, zone) from what the
 * connector's sensor reported it allows. Before the sensor reported its
 * allow-list (no sync yet) it falls back to a numeric id; the sensor refuses
 * anything outside its allow-list either way. Shared by the connector
 * settings and the scan wizard.
 */

import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { CatalogItem } from '@/features/integrations/lib/tenable-sc'
import { useTranslation } from '@/context/i18n-provider'

const NONE = '__none__'

interface CatalogSelectProps {
  id: string
  label: string
  items: CatalogItem[] | undefined
  value: number
  onChange: (id: number) => void
  /** Offer "None" (an optional field such as the zone). */
  optional?: boolean
  required?: boolean
}

export function CatalogSelect({
  id,
  label,
  items,
  value,
  onChange,
  optional = false,
  required = false,
}: CatalogSelectProps) {
  const { t } = useTranslation()
  const list = items ?? []
  const known = list.some((i) => i.id === value)

  return (
    <div className="space-y-2">
      <Label htmlFor={id}>
        {label} {required && <span className="text-destructive">*</span>}
      </Label>
      {list.length === 0 ? (
        <>
          <Input
            id={id}
            inputMode="numeric"
            placeholder={
              optional
                ? t('tenableSc.catalog.none', 'None')
                : t('tenableSc.catalog.idPlaceholder', 'Tenable.sc id')
            }
            value={value > 0 ? String(value) : ''}
            onChange={(e) => {
              const n = Number(e.target.value.trim())
              onChange(Number.isInteger(n) && n > 0 ? n : 0)
            }}
          />
          <p className="text-muted-foreground text-xs">
            {t(
              'tenableSc.catalog.notReported',
              'The sensor has not reported its allow-list yet (it does after the first sync). It refuses any id its owner did not allow.'
            )}
          </p>
        </>
      ) : (
        <Select
          value={value > 0 ? String(value) : optional ? NONE : undefined}
          onValueChange={(v) => onChange(v === NONE ? 0 : Number(v))}
        >
          <SelectTrigger id={id} aria-label={label}>
            <SelectValue
              placeholder={t('tenableSc.catalog.choose', 'Choose a {label}', {
                label: label.toLowerCase(),
              })}
            />
          </SelectTrigger>
          <SelectContent>
            {optional && (
              <SelectItem value={NONE}>{t('tenableSc.catalog.none', 'None')}</SelectItem>
            )}
            {value > 0 && !known && (
              <SelectItem value={String(value)}>
                {t('tenableSc.catalog.noLongerAllowed', '#{id} (no longer allowed by the sensor)', {
                  id: value,
                })}
              </SelectItem>
            )}
            {list.map((i) => (
              <SelectItem key={i.id} value={String(i.id)}>
                {i.name} (#{i.id})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </div>
  )
}
