'use client'

import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'

import { SensorOptInBanner } from './sensor-opt-in-banner'

export interface SensorOptInValue {
  allow_sensor_interactsh: boolean
  allow_sensor_custom_templates: boolean
}

const ITEMS: { key: keyof SensorOptInValue; id: string; label: string; help: string }[] = [
  {
    key: 'allow_sensor_interactsh',
    id: 'tenant-sensor-interactsh',
    label: 'Allow out-of-band callbacks (interactsh) in sensor jobs',
    help: 'Off: the platform sends no job that turns interactsh on and removes allow_interactsh from scans when they start. On: such jobs go only to sensors whose own local policy allows them; the callbacks reach an external server.',
  },
  {
    key: 'allow_sensor_custom_templates',
    id: 'tenant-sensor-custom-templates',
    label: 'Allow custom templates in sensor jobs',
    help: 'Off: scans with custom templates are refused when they start and none are sent. On: they go only to sensors whose local policy allows custom templates and that pin your template signing key.',
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
  return (
    <div className="space-y-4" data-testid="sensor-opt-in-switches">
      <SensorOptInBanner showSettingsLink={false} />
      {ITEMS.map((item) => (
        <div key={item.key} className="flex items-center justify-between gap-4">
          <div className="space-y-0.5">
            <Label htmlFor={item.id}>{item.label}</Label>
            <p className="text-sm text-muted-foreground" id={`${item.id}-desc`}>
              {item.help} Turning it on is audited and alerted.
            </p>
          </div>
          <Switch
            id={item.id}
            aria-describedby={`${item.id}-desc`}
            checked={value[item.key]}
            onCheckedChange={(checked) => onChange({ ...value, [item.key]: checked })}
            disabled={disabled}
          />
        </div>
      ))}
    </div>
  )
}
