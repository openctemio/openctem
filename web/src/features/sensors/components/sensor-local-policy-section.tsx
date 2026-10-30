'use client'

import { Lock, OctagonPause, ShieldAlert } from 'lucide-react'

import { HealthStatus } from '@/components/ui/health-status'
import type { HealthState } from '@/lib/health-colors'
import { useTranslation } from '@/context/i18n-provider'
import { DetailCallout, DetailField, DetailFieldGrid, DetailSection } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'

import { exactTime } from '../lib/format'
import {
  hasNoLocalPolicyWarning,
  localPolicySummaryLines,
  localPolicyView,
  noLocalPolicyGuidance,
  policyApplyCommand,
} from '../lib/local-policy'
import { Snippet, useSensorTemplates } from './sensor-install-snippets'

const TONE_STATE = {
  ok: 'ok',
  warn: 'warn',
  danger: 'down',
  muted: 'off',
} as const satisfies Record<string, HealthState>

/** The state of a sensor's local policy as a small badge (api RFC-040 §5.7). */
export function SensorLocalPolicyBadge({ sensor }: { sensor: Pick<Sensor, 'local_policy'> }) {
  const { t } = useTranslation()
  const view = localPolicyView(sensor.local_policy, t)
  return <HealthStatus state={TONE_STATE[view.tone]} label={view.label} title={view.description} />
}

/**
 * The policy the platform suggests for a sensor without one (its zones, else
 * the organization's scope), as one command that writes the file on the
 * host. The platform only proposes the text: the network owner reviews it
 * and runs it; the sensor enforces the file, which the platform cannot
 * change.
 */
export function SensorPolicySuggestion({ sensorId }: { sensorId: string }) {
  const { t } = useTranslation()
  const { data, loading, error } = useSensorTemplates(sensorId)
  const policy = data?.policy?.trim()
  if (loading || error || !policy) return null
  return (
    <div className="space-y-2" data-testid="policy-suggestion">
      <p className="text-sm font-medium">{t('sensors.localPolicy.suggest.title')}</p>
      <p className="text-sm text-muted-foreground">{t('sensors.localPolicy.suggest.body')}</p>
      <Snippet
        text={policyApplyCommand(policy)}
        label={t('sensors.localPolicy.suggest.title')}
        file="sensor-policy.sh"
      />
      <p className="text-xs text-muted-foreground">{t('sensors.localPolicy.suggest.reload')}</p>
    </div>
  )
}

/**
 * The sensor-local policy: written by the owner of the scanned network on the
 * sensor host, enforced there, and only reported here (state, digest and a
 * summary, never the ranges). The platform cannot change it.
 */
export function SensorLocalPolicySection({
  sensor,
}: {
  sensor: Pick<Sensor, 'local_policy'> & { id?: string }
}) {
  const { t } = useTranslation()
  const p = sensor.local_policy
  if (!p) return null
  const view = localPolicyView(p, t)
  const lines = localPolicySummaryLines(p, t)
  return (
    <DetailSection title={t('sensors.localPolicy.title')}>
      {p.state === 'paused' && (
        <DetailCallout
          tone="destructive"
          icon={OctagonPause}
          title={t('sensors.localPolicy.pausedTitle')}
        >
          {t('sensors.localPolicy.pausedBody')}
        </DetailCallout>
      )}
      {p.state === 'absent' && p.required && (
        <DetailCallout
          tone="destructive"
          icon={ShieldAlert}
          title={t('sensors.localPolicy.requiredTitle')}
        >
          {t('sensors.localPolicy.requiredBody')}
        </DetailCallout>
      )}
      {p.state === 'absent' && !p.required && (
        <DetailCallout tone="warning" icon={ShieldAlert} title={t('sensors.localPolicy.noneTitle')}>
          {t('sensors.localPolicy.noneBody')}
        </DetailCallout>
      )}
      {p.state === 'absent' && sensor.id && <SensorPolicySuggestion sensorId={sensor.id} />}
      {((p.state === 'absent' && !p.required) ||
        (p.state !== 'absent' && hasNoLocalPolicyWarning(p))) && (
        <ul className="space-y-0.5 text-sm text-muted-foreground" data-testid="no-policy-guidance">
          {noLocalPolicyGuidance(t).map((g) => (
            <li key={g}>{g}</li>
          ))}
        </ul>
      )}
      <DetailFieldGrid>
        <DetailField label={t('sensors.localPolicy.state')}>
          <span className="flex items-center gap-1.5">
            <Lock className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
            <SensorLocalPolicyBadge sensor={sensor} />
          </span>
        </DetailField>
        {p.digest && (
          <DetailField label={t('sensors.localPolicy.digest')} full>
            <code
              className="font-mono text-xs break-all select-all"
              data-testid="local-policy-digest"
              title={t('sensors.localPolicy.digestHint')}
            >
              {p.digest}
            </code>
          </DetailField>
        )}
        {p.source && (
          <DetailField label={t('sensors.localPolicy.source')}>
            {p.source === 'env'
              ? t('sensors.localPolicy.sourceEnv')
              : t('sensors.localPolicy.sourceFile')}
          </DetailField>
        )}
        {p.reported_at && (
          <DetailField label={t('sensors.localPolicy.reported')}>
            {exactTime(p.reported_at)}
          </DetailField>
        )}
        {lines.length > 0 && (
          <DetailField label={t('sensors.localPolicy.summary')} full>
            <ul className="space-y-0.5 text-sm">
              {lines.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </DetailField>
        )}
        {(p.warnings?.length ?? 0) > 0 && (
          <DetailField label={t('sensors.localPolicy.warnings')} full>
            <ul className="space-y-0.5 text-sm text-muted-foreground">
              {p.warnings?.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </DetailField>
        )}
      </DetailFieldGrid>
      <p className="text-xs text-muted-foreground">{view.description}</p>
    </DetailSection>
  )
}
