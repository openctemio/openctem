'use client'

/**
 * Scan intensity (RFC-071): the probe ceiling of a scan, asked first in the
 * wizard: one row of choices, the chosen one saying in plain words what it
 * does to the targets. A
 * passive-only organization (GET /scans/capabilities) is offered Passive
 * only, with one line saying why; the scanner and workflow choices below
 * follow the intensity, so they are passive too. The API enforces the same.
 */

import { useEffect } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { ChoiceGroup } from '@/components/ui/choice-group'
import { FormField } from '@/features/shared/components/forms'
import { SCAN_INTENSITIES, type ScanIntensity } from '@/lib/api/scan-types'
import { useScanCapabilities } from '../hooks/use-scan-capabilities'

interface IntensityPickerProps {
  value: ScanIntensity
  onChange: (value: ScanIntensity) => void
}

export function IntensityPicker({ value, onChange }: IntensityPickerProps) {
  const { t } = useTranslation()
  const { passiveOnly } = useScanCapabilities()
  const levels = passiveOnly ? (['passive'] as ScanIntensity[]) : SCAN_INTENSITIES
  // A passive-only organization cannot keep a higher intensity (a default
  // or a saved scan from before): the API would refuse it.
  useEffect(() => {
    if (passiveOnly && value !== 'passive') onChange('passive')
  }, [passiveOnly, value, onChange])
  return (
    <FormField
      group
      label={t('scans.intensity.label')}
      hint={passiveOnly ? t('scans.intensity.passiveOnly') : t('scans.intensity.hint')}
    >
      <ChoiceGroup<ScanIntensity>
        label={t('scans.intensity.label')}
        value={passiveOnly ? 'passive' : value}
        onValueChange={onChange}
        options={levels.map((level) => ({
          value: level,
          label: t(`scans.intensity.${level}`),
          hint: t(`scans.intensity.${level}Hint`),
        }))}
        data-testid="scan-intensity"
      />
    </FormField>
  )
}
