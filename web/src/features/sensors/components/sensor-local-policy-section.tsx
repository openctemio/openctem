'use client'

import { Lock, OctagonPause, ShieldAlert } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { DetailCallout, DetailField, DetailFieldGrid, DetailSection } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'
import { cn } from '@/lib/utils'

import { exactTime } from '../lib/format'
import {
  hasNoLocalPolicyWarning,
  localPolicySummaryLines,
  localPolicyView,
  noLocalPolicyGuidance,
} from '../lib/local-policy'

const TONE_CLASS = {
  ok: 'border-success/40 bg-success/10 text-success',
  warn: 'border-warning/40 bg-warning/10 text-warning',
  danger: 'border-destructive/40 bg-destructive/10 text-destructive',
  muted: 'text-muted-foreground',
} as const

/** The state of a sensor's local policy as a small badge (api RFC-040 §5.7). */
export function SensorLocalPolicyBadge({ sensor }: { sensor: Pick<Sensor, 'local_policy'> }) {
  const view = localPolicyView(sensor.local_policy)
  return (
    <Badge variant="outline" className={cn(TONE_CLASS[view.tone])} title={view.description}>
      {view.label}
    </Badge>
  )
}

/**
 * The sensor-local policy: written by the owner of the scanned network on the
 * sensor host, enforced there, and only reported here (state, digest and a
 * summary, never the ranges). The platform cannot change it.
 */
export function SensorLocalPolicySection({ sensor }: { sensor: Pick<Sensor, 'local_policy'> }) {
  const p = sensor.local_policy
  if (!p) return null
  const view = localPolicyView(p)
  const lines = localPolicySummaryLines(p)
  return (
    <DetailSection title="Local policy">
      {p.state === 'paused' && (
        <DetailCallout
          tone="destructive"
          icon={OctagonPause}
          title="Paused by the local kill switch"
        >
          The owner of this sensor host stopped every job. Jobs wait on the platform until the kill
          switch is released on the host.
        </DetailCallout>
      )}
      {p.state === 'absent' && p.required && (
        <DetailCallout
          tone="destructive"
          icon={ShieldAlert}
          title="Local policy required but missing"
        >
          This sensor refuses every job with a network target, custom templates and callbacks until
          the network owner installs a policy (the Local policy tab of the install commands).
        </DetailCallout>
      )}
      {p.state === 'absent' && !p.required && (
        <DetailCallout tone="warning" icon={ShieldAlert} title="No local policy">
          This sensor accepts any target outside its built-in deny list. Install the policy from the
          Install tab so the network owner decides what it may scan.
        </DetailCallout>
      )}
      {(p.state === 'absent' || hasNoLocalPolicyWarning(p)) && (
        <ul className="space-y-0.5 text-sm text-muted-foreground" data-testid="no-policy-guidance">
          {noLocalPolicyGuidance().map((g) => (
            <li key={g}>{g}</li>
          ))}
        </ul>
      )}
      <DetailFieldGrid>
        <DetailField label="State">
          <span className="flex items-center gap-1.5">
            <Lock className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
            <SensorLocalPolicyBadge sensor={sensor} />
          </span>
        </DetailField>
        {p.digest && (
          <DetailField label="Digest (sha256)" full>
            <code
              className="font-mono text-xs break-all select-all"
              data-testid="local-policy-digest"
              title="The digest the sensor reports for its local policy"
            >
              {p.digest}
            </code>
          </DetailField>
        )}
        {p.source && (
          <DetailField label="Source">
            {p.source === 'env' ? 'Environment' : 'Policy file'}
          </DetailField>
        )}
        {p.reported_at && <DetailField label="Reported">{exactTime(p.reported_at)}</DetailField>}
        {lines.length > 0 && (
          <DetailField label="Summary" full>
            <ul className="space-y-0.5 text-sm">
              {lines.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </DetailField>
        )}
        {(p.warnings?.length ?? 0) > 0 && (
          <DetailField label="Sensor warnings" full>
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
