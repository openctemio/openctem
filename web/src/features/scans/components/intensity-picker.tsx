'use client'

/**
 * Scan intensity (RFC-071): the probe ceiling of a scan, asked first in the
 * wizard. Each choice says in plain words what it does to the targets.
 */

import { Eye, Radar, Zap } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { SCAN_INTENSITIES, type ScanIntensity } from '@/lib/api/scan-types'

const ICONS: Record<ScanIntensity, React.ReactNode> = {
  passive: <Eye className="h-4 w-4" aria-hidden />,
  active: <Radar className="h-4 w-4" aria-hidden />,
  intrusive: <Zap className="h-4 w-4" aria-hidden />,
}

interface IntensityPickerProps {
  value: ScanIntensity
  onChange: (value: ScanIntensity) => void
}

export function IntensityPicker({ value, onChange }: IntensityPickerProps) {
  const { t } = useTranslation()
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{t('scans.intensity.label')}</legend>
      <p className="text-xs text-muted-foreground">{t('scans.intensity.hint')}</p>
      <RadioGroup
        value={value}
        onValueChange={(v) => onChange(v as ScanIntensity)}
        className="grid grid-cols-1 gap-2 sm:grid-cols-3"
      >
        {SCAN_INTENSITIES.map((level) => {
          const id = `scan-intensity-${level}`
          return (
            <Label
              key={level}
              htmlFor={id}
              className="flex cursor-pointer items-start gap-3 rounded-lg border p-3 font-normal hover:bg-muted/50 has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-primary/5"
            >
              <RadioGroupItem
                value={level}
                id={id}
                className="mt-0.5"
                aria-label={t(`scans.intensity.${level}`)}
              />
              <span className="min-w-0 space-y-1">
                <span className="flex items-center gap-1.5 text-sm font-medium">
                  {ICONS[level]}
                  {t(`scans.intensity.${level}`)}
                </span>
                <span className="block text-xs text-muted-foreground">
                  {t(`scans.intensity.${level}Hint`)}
                </span>
              </span>
            </Label>
          )
        })}
      </RadioGroup>
    </fieldset>
  )
}
