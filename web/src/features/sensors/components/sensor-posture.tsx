'use client'

import { ShieldAlert } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { DetailCallout, DetailField, DetailFieldGrid, DetailSection } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'
import { cn } from '@/lib/utils'

import {
  postureIssues,
  postureLocalPolicy,
  postureNetwork,
  posturePlatformPin,
  type PostureValue,
} from '../lib/posture'

const TONE_CLASS = {
  ok: 'border-success/40 bg-success/10 text-success',
  warn: 'border-warning/40 bg-warning/10 text-warning',
  muted: 'text-muted-foreground',
} as const

function PostureBadge({ value }: { value: PostureValue }) {
  const { t } = useTranslation()
  return (
    <Badge variant="outline" className={cn(TONE_CLASS[value.tone])}>
      {t(value.labelKey, value.label)}
    </Badge>
  )
}

/**
 * The sensor's security posture: its local policy, how it trusts the
 * platform and whether its tools are network-confined, as the sensor
 * reports them, with what to do for each weakness.
 */
export function SensorPostureSection({ sensor }: { sensor: Pick<Sensor, 'posture'> }) {
  const { t } = useTranslation()
  if (!sensor.posture) return null
  const issues = postureIssues(sensor)
  return (
    <DetailSection title={t('sensors.posture.title', 'Security posture')}>
      {issues.length > 0 && (
        <DetailCallout
          tone="warning"
          icon={ShieldAlert}
          title={t('sensors.posture.calloutTitle', 'This sensor runs unhardened')}
        >
          <ul className="space-y-0.5" data-testid="posture-fixes">
            {issues.map((i) => (
              <li key={i.reason} data-reason={i.reason}>
                <span className="font-medium">{t(i.labelKey, i.label)}:</span> {t(i.fixKey, i.fix)}
              </li>
            ))}
          </ul>
        </DetailCallout>
      )}
      <DetailFieldGrid>
        <DetailField label={t('sensors.posture.localPolicyLabel', 'Local policy')}>
          <PostureBadge value={postureLocalPolicy(sensor)} />
        </DetailField>
        <DetailField label={t('sensors.posture.platformPinLabel', 'Platform TLS')}>
          <PostureBadge value={posturePlatformPin(sensor)} />
        </DetailField>
        <DetailField label={t('sensors.posture.networkLabel', 'Tool network')}>
          <PostureBadge value={postureNetwork(sensor)} />
        </DetailField>
      </DetailFieldGrid>
      <p className="text-xs text-muted-foreground">
        {t(
          'sensors.posture.note',
          'Reported by the sensor. The platform flags a weak posture but never relaxes a check because of it.'
        )}
      </p>
    </DetailSection>
  )
}
