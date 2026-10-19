'use client'

import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import type { QualityGate } from '@/lib/api/scan-profile-types'

type Limit = 'max_critical' | 'max_high' | 'max_medium' | 'max_total'

const LIMITS: { key: Limit; labelKey: string }[] = [
  { key: 'max_critical', labelKey: 'scans.profiles.gate.maxCritical' },
  { key: 'max_high', labelKey: 'scans.profiles.gate.maxHigh' },
  { key: 'max_medium', labelKey: 'scans.profiles.gate.maxMedium' },
  { key: 'max_total', labelKey: 'scans.profiles.gate.maxTotal' },
]

interface QualityGateFieldsProps {
  value: QualityGate
  onChange: (next: QualityGate) => void
  disabled?: boolean
  idPrefix: string
}

/**
 * The pass/fail rule of a scan profile: the one thing a profile controls.
 * A limit left empty means unlimited (stored as -1).
 */
export function QualityGateFields({ value, onChange, disabled, idPrefix }: QualityGateFieldsProps) {
  const { t } = useTranslation()
  const set = (patch: Partial<QualityGate>) => onChange({ ...value, ...patch })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
        <div className="space-y-0.5">
          <Label htmlFor={`${idPrefix}-gate-enabled`}>{t('scans.profiles.gate.enabled')}</Label>
          <p className="text-muted-foreground text-xs">{t('scans.profiles.gate.enabledHelp')}</p>
        </div>
        <Switch
          id={`${idPrefix}-gate-enabled`}
          checked={value.enabled}
          disabled={disabled}
          onCheckedChange={(enabled) => set({ enabled })}
        />
      </div>

      {value.enabled && (
        <>
          <div className="space-y-2">
            {(
              [
                ['fail_on_critical', 'scans.profiles.gate.failOnCritical'],
                ['fail_on_high', 'scans.profiles.gate.failOnHigh'],
              ] as const
            ).map(([key, labelKey]) => (
              <div key={key} className="flex items-center gap-2">
                <Checkbox
                  id={`${idPrefix}-${key}`}
                  checked={value[key]}
                  disabled={disabled}
                  onCheckedChange={(checked) => set({ [key]: checked === true })}
                />
                <Label htmlFor={`${idPrefix}-${key}`} className="text-sm font-normal">
                  {t(labelKey)}
                </Label>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-4">
            {LIMITS.map(({ key, labelKey }) => (
              <div key={key} className="space-y-1.5">
                <Label htmlFor={`${idPrefix}-${key}`}>{t(labelKey)}</Label>
                <Input
                  id={`${idPrefix}-${key}`}
                  type="number"
                  min={0}
                  disabled={disabled}
                  placeholder={t('scans.profiles.gate.unlimited')}
                  value={value[key] < 0 ? '' : value[key]}
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10)
                    set({ [key]: Number.isFinite(n) && n >= 0 ? n : -1 })
                  }}
                />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
