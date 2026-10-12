'use client'

/**
 * What the finding's source knew (CTIS 1.4), as of its latest sighting:
 *
 *   Scores          every score with its system, version, source and date
 *   VEX             the latest exploitability statement and who made it
 *   Source record   the source's own id, severity, status, detection type,
 *                   credentialed flag and lifecycle (first / last found,
 *                   last fixed, times found)
 *   Fix             solution type, patch date, vendor advisories
 *   Source fields   unmapped fields, collapsed
 *
 * Every value is producer-supplied. It is rendered as text only (React
 * escapes it); free text goes through UntrustedTextBlock; advisory links go
 * through SafeExternalLink, so a javascript: or data: URL never becomes a
 * link.
 */

import { Database, Gauge, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import {
  DetailDisclosure,
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import { SafeExternalLink } from '@/components/safe-external-link'
import type { FindingSourceData, FindingSourceScore } from '../../types'

const SYSTEM_LABEL: Record<string, string> = {
  cvss: 'CVSS',
  epss: 'EPSS',
  epss_percentile: 'EPSS percentile',
  ssvc: 'SSVC',
  vpr: 'Tenable VPR',
  vendor: 'Vendor score',
}

const VEX_LABEL: Record<string, string> = {
  not_affected: 'Not affected',
  affected: 'Affected',
  fixed: 'Fixed',
  under_investigation: 'Under investigation',
}

const DETECTION_LABEL: Record<string, string> = {
  confirmed: 'Confirmed',
  potential: 'Potential',
  info: 'Information gathered',
}

function humanize(s: string): string {
  return s.replace(/_/g, ' ')
}

function day(iso?: string): string | undefined {
  if (!iso) return undefined
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return undefined
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[13px] break-all">{children}</span>
}

/** The value of a score as people read it: EPSS as a percentage. */
export function formatScoreValue(s: FindingSourceScore): string | undefined {
  if (s.value === undefined || s.value === null) return s.label || undefined
  if (s.system === 'epss' || s.system === 'epss_percentile') {
    return `${(s.value * 100).toFixed(s.value < 0.1 ? 2 : 1)}%`
  }
  return s.value.toFixed(1)
}

function ScoreRow({ score }: { score: FindingSourceScore }) {
  const name = `${SYSTEM_LABEL[score.system] ?? humanize(score.system)}${score.version ? ` ${score.version}` : ''}`
  const value = formatScoreValue(score)
  const when = day(score.asOf)
  return (
    <li className="space-y-0.5" data-testid="source-score">
      <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
        <span className="font-medium">{name}</span>
        {value && <span className="tabular-nums">{value}</span>}
        {score.label && score.value !== undefined && (
          <span className="text-muted-foreground">· {score.label}</span>
        )}
        {score.source && <span className="text-xs text-muted-foreground">from {score.source}</span>}
        {when && <span className="text-xs text-muted-foreground">· {when}</span>}
      </div>
      {score.vector && (
        <div className="text-muted-foreground">
          <Mono>{score.vector}</Mono>
        </div>
      )}
    </li>
  )
}

export function SourceDataSection({ data }: { data: FindingSourceData }) {
  const n = data.native
  const l = data.lifecycle
  const sol = data.solution
  const vex = data.vex
  const hasRecord = !!n || !!l || data.vulnerabilityIds.length > 0 || !!data.locationKey
  return (
    <>
      {data.scores.length > 0 && (
        <DetailSection title="Scores by source" icon={Gauge} count={data.scores.length}>
          <ul className="space-y-2">
            {data.scores.map((s, i) => (
              <ScoreRow key={`${s.system}-${s.version ?? ''}-${s.source ?? ''}-${i}`} score={s} />
            ))}
          </ul>
        </DetailSection>
      )}

      {vex && (
        <DetailSection title="VEX statement" icon={ShieldCheck}>
          <DetailFieldGrid>
            <DetailField label="Status">
              <Badge variant={vex.status === 'not_affected' ? 'secondary' : 'outline'}>
                {VEX_LABEL[vex.status] ?? humanize(vex.status)}
              </Badge>
            </DetailField>
            <DetailField label="Justification">
              {vex.justification ? humanize(vex.justification) : null}
            </DetailField>
            <DetailField label="Stated by" full>
              {vex.source ? <Mono>{vex.source}</Mono> : null}
            </DetailField>
            <DetailField label="Stated on">{day(vex.asOf)}</DetailField>
          </DetailFieldGrid>
          {vex.statement && (
            <UntrustedTextBlock className="mt-2" text={vex.statement} label="VEX statement" />
          )}
        </DetailSection>
      )}

      {(hasRecord || sol || data.sourceExtra.length > 0) && (
        <DetailSection title="Source record" icon={Database}>
          <DetailFieldGrid>
            <DetailField label="Source check id">
              {n?.vulnId ? (
                <Mono>
                  {n.scheme ? `${n.scheme} ` : ''}
                  {n.vulnId}
                </Mono>
              ) : null}
            </DetailField>
            <DetailField label="Source severity">{n?.severity}</DetailField>
            <DetailField label="Source status">{n?.status}</DetailField>
            <DetailField label="Detection">
              {n?.detectionType
                ? (DETECTION_LABEL[n.detectionType] ?? humanize(n.detectionType))
                : null}
            </DetailField>
            <DetailField label="Credentialed scan">
              {n?.credentialed === undefined ? null : n.credentialed ? 'Yes' : 'No'}
            </DetailField>
            <DetailField label="Family">{n?.family}</DetailField>
            <DetailField label="First found (source)">{day(l?.firstFound)}</DetailField>
            <DetailField label="Last found (source)">{day(l?.lastFound)}</DetailField>
            <DetailField label="Last fixed (source)">{day(l?.lastFixed)}</DetailField>
            <DetailField label="Times found">
              {l?.timesFound ? <span className="tabular-nums">{l.timesFound}</span> : null}
            </DetailField>
            <DetailField label="Source state">{l?.state ? humanize(l.state) : null}</DetailField>
            <DetailField label="Location">
              {data.locationKey ? <Mono>{data.locationKey}</Mono> : null}
            </DetailField>
            <DetailField label="Vulnerability ids" full>
              {data.vulnerabilityIds.length > 0 ? (
                <span className="flex flex-wrap gap-1.5" data-testid="source-vuln-ids">
                  {data.vulnerabilityIds.map((v) => (
                    <Badge
                      key={`${v.type}:${v.id}`}
                      variant="outline"
                      className="font-mono text-xs"
                    >
                      {v.id}
                    </Badge>
                  ))}
                </span>
              ) : null}
            </DetailField>
            <DetailField label="Fix type">{sol?.type ? humanize(sol.type) : null}</DetailField>
            <DetailField label="Patch published">{day(sol?.patchPublishedAt)}</DetailField>
            <DetailField label="Advisories" full>
              {sol && sol.advisories.length > 0 ? (
                <span className="flex flex-wrap gap-x-3 gap-y-1">
                  {sol.advisories.map((a, i) => {
                    const text = a.id || a.url || ''
                    return a.url ? (
                      <SafeExternalLink
                        key={`${text}-${i}`}
                        href={a.url}
                        className="text-primary hover:underline"
                      >
                        {text}
                      </SafeExternalLink>
                    ) : (
                      <span key={`${text}-${i}`}>{text}</span>
                    )
                  })}
                </span>
              ) : null}
            </DetailField>
            <DetailField label="Raw record" full>
              {n?.rawRef ? <Mono>{n.rawRef}</Mono> : null}
            </DetailField>
          </DetailFieldGrid>
          {data.sourceExtra.length > 0 && (
            <DetailDisclosure summary={`Other source fields (${data.sourceExtra.length})`}>
              <dl className="mt-2 grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
                {data.sourceExtra.map(([k, v]) => (
                  <div key={k} className="min-w-0">
                    <dt className="text-xs break-all text-muted-foreground">{k}</dt>
                    <dd className="text-sm break-words whitespace-pre-wrap">{v}</dd>
                  </div>
                ))}
              </dl>
            </DetailDisclosure>
          )}
        </DetailSection>
      )}
    </>
  )
}
