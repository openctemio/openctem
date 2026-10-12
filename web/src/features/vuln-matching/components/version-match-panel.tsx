'use client'

import { Scale } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { DetailSection, UntrustedTextBlock } from '@/features/shared'

import { reasonLabel, versionMatchEvidence } from '../types'

interface VersionMatchPanelProps {
  metadata: Record<string, unknown> | undefined
}

/**
 * "Why this finding" for a finding the vulnerability matcher created
 * (RFC-066): the software version a scan saw, the advisory range it falls
 * in, and what lowered the confidence. Renders nothing for other findings.
 */
export function VersionMatchPanel({ metadata }: VersionMatchPanelProps) {
  const ev = versionMatchEvidence(metadata)
  if (!ev) return null
  const likely = ev.label === 'likely'
  return (
    <DetailSection title="Why this finding" icon={Scale}>
      <div className="space-y-3 text-sm">
        <p>
          A scan saw{' '}
          <span className="font-medium">
            {[ev.vendor, ev.product].filter(Boolean).join(' ')} {ev.version}
          </span>
          {ev.location ? ` on ${ev.location}` : ''}, and the advisory lists that version as
          affected. Nothing has exploited or probed it: the version alone is the evidence.
        </p>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant={likely ? 'default' : 'outline'}>
            {likely ? 'Likely' : 'Potential'}
            {ev.confidence != null ? ` · confidence ${ev.confidence}` : ''}
          </Badge>
          {ev.qualifier && (
            <Badge
              variant="outline"
              title="Distribution build: the vendor may have back-ported fixes"
            >
              {ev.qualifier}
            </Badge>
          )}
          {ev.source && <Badge variant="secondary">Source: {ev.source.toUpperCase()}</Badge>}
        </div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
          <dt className="text-muted-foreground">Affected range</dt>
          <dd className="tabular-nums">{ev.range || 'not stated'}</dd>
          <dt className="text-muted-foreground">Observed version</dt>
          <dd className="tabular-nums">{ev.version || 'unknown'}</dd>
        </dl>
        {(ev.reasons ?? []).length > 0 && (
          <div>
            <p className="text-muted-foreground">Confidence lowered because:</p>
            <ul className="list-disc pl-5">
              {(ev.reasons ?? []).map((r) => (
                <li key={r}>{reasonLabel(r)}</li>
              ))}
            </ul>
          </div>
        )}
        {ev.evidence && <UntrustedTextBlock label="What the scan reported" text={ev.evidence} />}
        <p className="text-xs text-muted-foreground">
          Upgrading out of the range resolves this finding on the next scan; a scanner or a
          validation that confirms it replaces this evidence.
        </p>
      </div>
    </DetailSection>
  )
}
