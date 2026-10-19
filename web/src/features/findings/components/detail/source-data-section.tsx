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

import { useTranslation } from '@/context/i18n-provider'
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
import Link from '@/components/link'
import type { FindingSourceData, FindingSourceScore } from '../../types'

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

// Ids with a fixed English label; the label is translated at render.
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

/** The translated label for a known id, or the humanized id when it is unknown. */
function knownLabel(
  t: Translate,
  group: 'system' | 'vex' | 'detection',
  labels: Record<string, string>,
  id: string
): string {
  const en = labels[id]
  return en === undefined ? humanize(id) : t(`findings.sourceData.${group}.${id}`, en)
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
  const { t } = useTranslation()
  const name = `${knownLabel(t, 'system', SYSTEM_LABEL, score.system)}${score.version ? ` ${score.version}` : ''}`
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
        {score.source && (
          <span className="text-xs text-muted-foreground">
            {t('findings.sourceData.from', 'from {source}', { source: score.source })}
          </span>
        )}
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

export function SourceDataSection({
  data,
  ruleName,
}: {
  data: FindingSourceData
  ruleName?: string
}) {
  const { t } = useTranslation()
  const n = data.native
  const l = data.lifecycle
  const sol = data.solution
  const vex = data.vex
  const hasRecord =
    !!n || !!l || data.vulnerabilityIds.length > 0 || !!data.locationKey || !!data.rule
  return (
    <>
      {data.scores.length > 0 && (
        <DetailSection
          title={t('findings.sourceData.scoresBySource', 'Scores by source')}
          icon={Gauge}
          count={data.scores.length}
        >
          <ul className="space-y-2">
            {data.scores.map((s, i) => (
              <ScoreRow key={`${s.system}-${s.version ?? ''}-${s.source ?? ''}-${i}`} score={s} />
            ))}
          </ul>
        </DetailSection>
      )}

      {vex && (
        <DetailSection
          title={t('findings.sourceData.vexStatement', 'VEX statement')}
          icon={ShieldCheck}
        >
          <DetailFieldGrid>
            <DetailField label={t('findings.sourceData.status', 'Status')}>
              <Badge variant={vex.status === 'not_affected' ? 'secondary' : 'outline'}>
                {knownLabel(t, 'vex', VEX_LABEL, vex.status)}
              </Badge>
            </DetailField>
            <DetailField label={t('findings.sourceData.justification', 'Justification')}>
              {vex.justification ? humanize(vex.justification) : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.statedBy', 'Stated by')} full>
              {vex.source ? <Mono>{vex.source}</Mono> : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.statedOn', 'Stated on')}>
              {day(vex.asOf)}
            </DetailField>
          </DetailFieldGrid>
          {vex.statement && (
            <UntrustedTextBlock
              className="mt-2"
              text={vex.statement}
              label={t('findings.sourceData.vexStatement', 'VEX statement')}
            />
          )}
        </DetailSection>
      )}

      {(hasRecord || sol || data.sourceExtra.length > 0) && (
        <DetailSection
          title={t('findings.sourceData.sourceRecord', 'Source record')}
          icon={Database}
        >
          <DetailFieldGrid>
            <DetailField label={t('findings.sourceData.checkId', 'Source check id')}>
              {n?.vulnId ? (
                <Mono>
                  {n.scheme ? `${n.scheme} ` : ''}
                  {n.vulnId}
                </Mono>
              ) : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.srcSeverity', 'Source severity')}>
              {n?.severity}
            </DetailField>
            <DetailField label={t('findings.sourceData.srcStatus', 'Source status')}>
              {n?.status}
            </DetailField>
            <DetailField label={t('findings.sourceData.detection', 'Detection')}>
              {n?.detectionType
                ? knownLabel(t, 'detection', DETECTION_LABEL, n.detectionType)
                : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.credentialed', 'Credentialed scan')}>
              {n?.credentialed === undefined
                ? null
                : n.credentialed
                  ? t('findings.sourceData.yes', 'Yes')
                  : t('findings.sourceData.no', 'No')}
            </DetailField>
            <DetailField label={t('findings.sourceData.family', 'Family')}>{n?.family}</DetailField>
            <DetailField label={t('findings.sourceData.firstFound', 'First found (source)')}>
              {day(l?.firstFound)}
            </DetailField>
            <DetailField label={t('findings.sourceData.lastFound', 'Last found (source)')}>
              {day(l?.lastFound)}
            </DetailField>
            <DetailField label={t('findings.sourceData.lastFixed', 'Last fixed (source)')}>
              {day(l?.lastFixed)}
            </DetailField>
            <DetailField label={t('findings.sourceData.timesFound', 'Times found')}>
              {l?.timesFound ? <span className="tabular-nums">{l.timesFound}</span> : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.srcState', 'Source state')}>
              {l?.state ? humanize(l.state) : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.location', 'Location')}>
              {data.locationKey ? <Mono>{data.locationKey}</Mono> : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.vulnIds', 'Vulnerability ids')} full>
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
            <DetailField label={t('findings.sourceData.fixType', 'Fix type')}>
              {sol?.type ? humanize(sol.type) : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.patchPublished', 'Patch published')}>
              {day(sol?.patchPublishedAt)}
            </DetailField>
            <DetailField label={t('findings.sourceData.advisories', 'Advisories')} full>
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
            <DetailField label={t('findings.sourceData.detectionRule', 'Detection rule')} full>
              {data.rule || n?.vulnId ? (
                <span className="space-y-0.5" data-testid="source-detection-rule">
                  <span className="block text-sm">
                    {[n?.vulnId, ruleName && ruleName !== n?.vulnId ? ruleName : undefined]
                      .filter(Boolean)
                      .join(' · ')}
                  </span>
                  {data.rule?.source && (
                    <Badge variant="outline" className="text-xs" data-testid="source-rule-source">
                      {data.rule.source === 'tenant'
                        ? t('findings.sourceData.ruleSourceTenant', 'Organization template')
                        : t('findings.sourceData.ruleSourcePlatform', 'Platform rules')}
                    </Badge>
                  )}
                  {data.rule?.source === 'tenant' && (
                    <span
                      className="block text-xs text-muted-foreground"
                      data-testid="source-rule-template"
                    >
                      {data.rule.template_name ? (
                        <Link
                          href={`/settings/scanning/templates?q=${encodeURIComponent(data.rule.template_name)}`}
                          className="underline-offset-2 hover:underline"
                        >
                          {data.rule.template_version
                            ? `${data.rule.template_name}@${data.rule.template_version}`
                            : data.rule.template_name}
                        </Link>
                      ) : (
                        t('findings.sourceData.ruleTemplateDeleted', 'Template deleted')
                      )}
                    </span>
                  )}
                  {data.rule?.pack && (
                    <span className="block text-xs text-muted-foreground">
                      {data.rule.version
                        ? `${data.rule.pack}@${data.rule.version}`
                        : data.rule.pack}
                    </span>
                  )}
                  {data.rule?.path && (
                    <span className="block">
                      <Mono>{data.rule.path}</Mono>
                    </span>
                  )}
                </span>
              ) : null}
            </DetailField>
            <DetailField label={t('findings.sourceData.rawRecord', 'Raw record')} full>
              {n?.rawRef ? <Mono>{n.rawRef}</Mono> : null}
            </DetailField>
          </DetailFieldGrid>
          {data.sourceExtra.length > 0 && (
            <DetailDisclosure
              summary={t('findings.sourceData.otherFields', 'Other source fields ({count})', {
                count: data.sourceExtra.length,
              })}
            >
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
