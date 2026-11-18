'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsRow } from '@/features/shared'
import { Switch } from '@/components/ui/switch'

import { SensorOptInBanner } from './sensor-opt-in-banner'

export interface SensorOptInValue {
  allow_sensor_interactsh: boolean
  allow_sensor_custom_templates: boolean
}

const ITEMS: {
  key: keyof SensorOptInValue
  id: string
  label: string
  help: string
  /**
   * The names an operator meets on the sensor and in scan options, shown as
   * secondary help in mono (the label and the hint stay in plain words).
   */
  tech?: string
}[] = [
  {
    key: 'allow_sensor_interactsh',
    id: 'tenant-sensor-interactsh',
    label: 'sensors.optIns.interactsh.label',
    help: 'sensors.optIns.interactsh.help',
    tech: 'interactsh, allow_interactsh, SENSOR_OOB_SERVER',
  },
  {
    key: 'allow_sensor_custom_templates',
    id: 'tenant-sensor-custom-templates',
    label: 'sensors.optIns.customTemplates.label',
    help: 'sensors.optIns.customTemplates.help',
  },
]

/**
 * The organization's sensor opt-ins (api research/25 D3), off by default.
 * Only an owner can change them; turning one on is audited at critical
 * severity and alerted. The platform never overrides a sensor's own local
 * policy: these switches only decide whether such jobs are sent at all.
 */
export function SensorOptInSwitches({
  value,
  onChange,
  disabled,
}: {
  value: SensorOptInValue
  onChange: (next: SensorOptInValue) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div data-testid="sensor-opt-in-switches">
      <SensorOptInBanner showSettingsLink={false} />
      {ITEMS.map((item) => (
        <SettingsRow
          key={item.key}
          label={<label htmlFor={item.id}>{t(item.label)}</label>}
          hintId={`${item.id}-desc`}
          hint={
            <>
              {t(item.help)} {t('sensors.optIns.audited')}
              {item.tech && (
                <span className="mt-1 block" data-slot="settings-row-tech">
                  {t('sensors.optIns.techNames', 'Technical names:')}{' '}
                  <span className="font-mono">{item.tech}</span>
                </span>
              )}
            </>
          }
        >
          <Switch
            id={item.id}
            aria-describedby={`${item.id}-desc`}
            checked={value[item.key]}
            onCheckedChange={(checked) => onChange({ ...value, [item.key]: checked })}
            disabled={disabled}
          />
        </SettingsRow>
      ))}
    </div>
  )
}
