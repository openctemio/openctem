'use client'

import { SelectItem } from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'

/** The four ownership types as select options, with what each one means. */
export function OwnershipSelectItems() {
  const { t } = useTranslation()
  const options = [
    {
      value: 'primary',
      label: t('assets.ownershipType.primary', 'Primary'),
      hint: t('org.ownership.primaryHint', 'Main owner with full access and responsibility'),
    },
    {
      value: 'secondary',
      label: t('assets.ownershipType.secondary', 'Secondary'),
      hint: t('org.ownership.secondaryHint', 'Co-owner with full access and shared responsibility'),
    },
    {
      value: 'stakeholder',
      label: t('assets.ownershipType.stakeholder', 'Stakeholder'),
      hint: t('org.ownership.stakeholderHint', 'View access, receives critical notifications'),
    },
    {
      value: 'informed',
      label: t('assets.ownershipType.informed', 'Informed'),
      hint: t('org.ownership.informedHint', 'No direct access, receives summary notifications'),
    },
  ]
  return (
    <>
      {options.map((o) => (
        <SelectItem key={o.value} value={o.value}>
          <div className="flex flex-col">
            <span className="font-medium">{o.label}</span>
            <span className="text-xs text-muted-foreground">{o.hint}</span>
          </div>
        </SelectItem>
      ))}
    </>
  )
}
