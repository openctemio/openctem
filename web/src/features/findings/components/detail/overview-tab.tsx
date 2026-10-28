'use client'

/**
 * Overview tab: what the finding is, in reading order.
 *
 *   AI analysis (when a triage ran)
 *   Description          the advisory text, not the title again
 *   <type sections>      package / credential / resource / endpoint / control
 *   Code location        file, lines, snippet
 *   Context              scanner-supplied impact, likelihood, attack vector
 *   Scanner output       the scanner's proof (plugin output), escaped, with Copy
 *   Source data          every score with its source, VEX, the source's own
 *                        record (CTIS 1.4), escaped
 *   Identifiers          CVSS (v2 and v3 vectors), CVE (all of them, related),
 *                        CWE, OWASP, EPSS, VPR as an input, family, patch date
 *   More details         rule, tool, classification, raw scanner metadata
 *
 * Status, owner, SLA and asset live in the properties rail; priority and its
 * reasons in "Why it matters"; the fix in the Fix card. Nothing here repeats
 * them.
 */

import { CveLink } from '@/features/vulnerabilities/components/cve-link'
import { isCveId } from '@/features/vulnerabilities/lib/vuln-page'
import { FindingLastSeenIn } from '../receipt-summary'
import { useMemo } from 'react'
import Link from '@/components/link'
import {
  ArrowUpRight,
  Bot,
  ExternalLink,
  FileText,
  Fingerprint,
  Terminal,
  Server,
  ShieldAlert,
} from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { MarkdownPreview } from '@/components/ui/markdown-editor'
import {
  DetailDisclosure,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
} from '@/features/shared/components/detail-sheet'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import { useTriageResult } from '@/features/ai-triage/api'
import { AISuggestionsPanel } from '@/features/ai-suggestions/components/ai-suggestions-panel'
import { AIBadge } from '@/features/shared/components/ai-badge'
import { useRelatedCVEs } from '../../api/use-finding-groups'
import { formatEpssPercentile } from '@/lib/epss'
import { EpssChip } from '@/components/ui/epss-chip'
import { KevBadge } from '@/components/ui/kev-badge'
import { cn, sanitizeExternalUrl } from '@/lib/utils'
import type { FindingDetail } from '../../types'
import { FINDING_TYPE_CONFIG } from '../../types'
import { MetadataViewer } from './source-panels/metadata-viewer'
import { SourceDataSection } from './source-data-section'
import { VersionMatchPanel } from '@/features/vuln-matching/components/version-match-panel'
import { VERSION_MATCH_TOOL } from '@/features/vuln-matching/types'
import { findingTypeSections } from './finding-type-details'
import { assetDetailHref, isLinkableAssetId } from '../../lib/asset-link'
import { findingAssetTypeLabel } from '../../lib/finding-asset-type'
import { HUMAN_SOURCES, findingDescription } from '../../lib/finding-detail'
import { FindingCodeLocation, codeLocationOf } from './finding-code-location'
import { FindingIssueGroupSection } from './finding-issue-group-section'
import { FindingIdentitySection } from './finding-identity-section'

interface OverviewTabProps {
  finding: FindingDetail
}

/** The latest completed AI triage of the finding (its own endpoint). */
interface AITriageSummaryData {
  riskScore?: number
  riskLevel?: string
  /** 0-1: how likely the model thinks the finding is a false positive. */
  falsePositiveLikelihood?: number
  recommendation?: string
  createdAt: string
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[13px] break-all">{children}</span>
}

export function OverviewTab({ finding }: OverviewTabProps) {
  const { t, locale } = useTranslation()
  const isHuman = HUMAN_SOURCES.has(finding.source)

  // Read from the AI triage endpoint, not from the first page of activities:
  // twenty newer comments must not hide the analysis. Not requested without
  // ai_triage:read (the hook sends no request then).
  const { data: triageResult } = useTriageResult(finding.id)
  const triage: AITriageSummaryData | null = useMemo(() => {
    if (!triageResult || triageResult.status !== 'completed') return null
    return {
      riskScore: triageResult.riskScore,
      riskLevel: triageResult.severityAssessment,
      falsePositiveLikelihood: triageResult.falsePositiveLikelihood,
      recommendation: triageResult.summary,
      createdAt: triageResult.completedAt ?? triageResult.createdAt,
    }
  }, [triageResult])

  const desc = findingDescription(finding)
  const adv = finding.advisory
  const hasContext =
    finding.confidence !== undefined ||
    !!finding.impact ||
    !!finding.likelihood ||
    (!!finding.exposureVector && finding.exposureVector !== 'unknown') ||
    !!finding.attackPrerequisites ||
    !!finding.dataExposureRisk ||
    finding.reputationalImpact !== undefined ||
    (finding.complianceImpact?.length ?? 0) > 0
  const metadataKeys = Object.keys(finding.metadata ?? {}).filter(
    (k) => finding.metadata![k] != null && finding.metadata![k] !== '' && !k.startsWith('_')
  )
  const typeCfg = finding.findingType ? FINDING_TYPE_CONFIG[finding.findingType] : undefined
  // Pentest-style findings can name several targets; scanner findings have one
  // asset, shown in the properties rail.
  const extraAssets = isHuman && finding.assets.length > 1 ? finding.assets : []

  return (
    <DetailSections>
      {triage && <AITriageSummary data={triage} />}
      <AISuggestionsPanel findingId={finding.id} />

      <DetailSection title={t('findings.overviewTab.description', 'Description')} icon={FileText}>
        {desc.text ? (
          isHuman ? (
            <MarkdownPreview content={desc.text} />
          ) : (
            <p className="text-sm leading-relaxed whitespace-pre-wrap">{desc.text}</p>
          )
        ) : (
          <p className="text-sm text-muted-foreground">
            {t('findings.overviewTab.noDescription', 'The scanner sent no description.')}
          </p>
        )}
        {desc.fromAdvisory && adv?.cveId && (
          <p className="text-xs text-muted-foreground">
            {t('findings.overviewTab.fromAdvisory', 'From the {cve} advisory.', { cve: adv.cveId })}
          </p>
        )}
      </DetailSection>

      {findingTypeSections(finding)}

      {(finding.filePath || finding.snippet || finding.contextSnippet) && (
        <FindingCodeLocation location={codeLocationOf(finding)} />
      )}

      <FindingIssueGroupSection findingId={finding.id} />

      {finding.scannerOutput && <ScannerOutputSection output={finding.scannerOutput} />}

      {finding.toolName === VERSION_MATCH_TOOL && <VersionMatchPanel metadata={finding.metadata} />}

      {finding.sourceData && (
        <SourceDataSection data={finding.sourceData} ruleName={finding.ruleName} />
      )}

      {extraAssets.length > 0 && (
        <DetailSection
          title={t('findings.overviewTab.targets', 'Targets')}
          icon={Server}
          count={extraAssets.length}
        >
          <ul className="space-y-1.5">
            {extraAssets.map((a) => (
              <li key={a.id} className="flex items-center gap-2 text-sm">
                <Badge variant="outline" className="text-xs">
                  {findingAssetTypeLabel(a.type)}
                </Badge>
                {isLinkableAssetId(a.id) ? (
                  <Link
                    href={assetDetailHref(a.id)}
                    className="inline-flex items-center gap-1 hover:underline"
                  >
                    {a.name}
                    <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
                  </Link>
                ) : (
                  <span>{a.name}</span>
                )}
              </li>
            ))}
          </ul>
        </DetailSection>
      )}

      {hasContext && (
        <DetailSection title={t('findings.overviewTab.context', 'Context')} icon={ShieldAlert}>
          <DetailFieldGrid>
            <DetailField label={t('findings.overviewTab.attackVector', 'Attack vector')}>
              {finding.exposureVector && finding.exposureVector !== 'unknown' ? (
                <span className="capitalize">{finding.exposureVector}</span>
              ) : null}
            </DetailField>
            <DetailField label={t('findings.overviewTab.impact', 'Impact')}>
              {finding.impact ? <span className="capitalize">{finding.impact}</span> : null}
            </DetailField>
            <DetailField label={t('findings.overviewTab.likelihood', 'Likelihood')}>
              {finding.likelihood ? <span className="capitalize">{finding.likelihood}</span> : null}
            </DetailField>
            <DetailField label={t('findings.overviewTab.scannerConfidence', 'Scanner confidence')}>
              {finding.confidence !== undefined ? `${finding.confidence}%` : null}
            </DetailField>
            <DetailField label={t('findings.overviewTab.dataExposure', 'Data exposure')}>
              {finding.dataExposureRisk && finding.dataExposureRisk !== 'none' ? (
                <span className="capitalize">{finding.dataExposureRisk}</span>
              ) : null}
            </DetailField>
            <DetailField
              label={t('findings.overviewTab.reputationalImpact', 'Reputational impact')}
            >
              {finding.reputationalImpact ? t('findings.overviewTab.yes', 'Yes') : null}
            </DetailField>
            <DetailField label={t('findings.overviewTab.prerequisites', 'Prerequisites')} full>
              {finding.attackPrerequisites}
            </DetailField>
            <DetailField
              label={t('findings.overviewTab.complianceImpact', 'Compliance impact')}
              full
            >
              {finding.complianceImpact && finding.complianceImpact.length > 0 ? (
                <span className="flex flex-wrap gap-1">
                  {finding.complianceImpact.map((c) => (
                    <Badge key={c} variant="outline" className="text-xs">
                      {c}
                    </Badge>
                  ))}
                </span>
              ) : null}
            </DetailField>
          </DetailFieldGrid>
        </DetailSection>
      )}

      <IdentifiersSection finding={finding} />

      <FindingIdentitySection findingId={finding.id} />

      {!isHuman && (
        <DetailDisclosure summary={t('findings.overviewTab.moreDetails', 'More details')}>
          <div className="mt-3 space-y-4">
            <DetailFieldGrid>
              <DetailField label={t('findings.overviewTab.rule', 'Rule')}>
                {finding.ruleId ? (
                  <span>
                    <Mono>{finding.ruleId}</Mono>
                    {finding.ruleName && finding.ruleName !== finding.ruleId && (
                      <span className="block text-muted-foreground">{finding.ruleName}</span>
                    )}
                  </span>
                ) : null}
              </DetailField>
              <DetailField label={t('findings.overviewTab.tool', 'Tool')}>
                {[finding.toolName, finding.toolVersion].filter(Boolean).join(' ') || null}
              </DetailField>
              <DetailField label={t('findings.overviewTab.findingType', 'Finding type')}>
                {typeCfg?.label}
              </DetailField>
              <DetailField label={t('findings.overviewTab.classification', 'Classification')}>
                {finding.vulnerabilityClass?.length ? finding.vulnerabilityClass.join(', ') : null}
              </DetailField>
              <DetailField label={t('findings.overviewTab.remediationType', 'Remediation type')}>
                {finding.remediationType ? (
                  <span className="capitalize">{finding.remediationType}</span>
                ) : null}
              </DetailField>
              <DetailField label={t('findings.overviewTab.fixComplexity', 'Fix complexity')}>
                {finding.fixComplexity ? (
                  <span className="capitalize">{finding.fixComplexity}</span>
                ) : null}
              </DetailField>
              <DetailField label={t('findings.overviewTab.scan', 'Scan')}>
                {/* The id of the report that carried this finding, not a run id;
                    "Last seen in" below links the run. */}
                {finding.scanId ? <Mono>{finding.scanId}</Mono> : null}
              </DetailField>
              <DetailField label={t('findings.receipts.lastSeenIn', 'Last seen in')}>
                <FindingLastSeenIn findingId={finding.id} />
              </DetailField>
              <DetailField label={t('findings.overviewTab.recorded', 'Recorded')}>
                {new Date(finding.createdAt).toLocaleString(locale, {
                  dateStyle: 'medium',
                  timeStyle: 'short',
                })}
              </DetailField>
            </DetailFieldGrid>
            {metadataKeys.length > 0 && finding.metadata && (
              <MetadataViewer metadata={finding.metadata} />
            )}
          </div>
        </DetailDisclosure>
      )}
    </DetailSections>
  )
}

function formatDay(iso: string, locale: string): string {
  return new Date(iso).toLocaleDateString(locale, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

/**
 * The scanner's output (Nessus plugin output, a tool's proof). Attacker-
 * influenced: shown through UntrustedTextBlock (escaped, never markup), with
 * when the latest sighting wrote it. Collapsed by default.
 */
function ScannerOutputSection({ output }: { output: NonNullable<FindingDetail['scannerOutput']> }) {
  const { t, locale } = useTranslation()
  return (
    <DetailSection
      title={t('findings.overviewTab.scannerOutput', 'Scanner output')}
      icon={Terminal}
    >
      <p className="text-xs text-muted-foreground">
        {t('findings.overviewTab.printedProof', 'What the scanner printed as its proof')}
        {output.updatedAt && (
          <>
            ,{' '}
            {t('findings.overviewTab.fromSighting', 'from the sighting of {date}', {
              date: formatDay(output.updatedAt, locale),
            })}
          </>
        )}
        {output.truncated && <>, {t('findings.overviewTab.cutAt', 'cut at 64 KiB')}</>}.{' '}
        {t('findings.overviewTab.shownPlain', 'Shown as plain text.')}
      </p>
      <DetailDisclosure summary={t('findings.overviewTab.showOutput', 'Show output')}>
        <UntrustedTextBlock
          className="mt-2"
          text={output.text}
          label={t('findings.overviewTab.scannerOutput', 'Scanner output')}
        />
      </DetailDisclosure>
    </DetailSection>
  )
}

function IdentifiersSection({ finding }: { finding: FindingDetail }) {
  const { t, locale } = useTranslation()
  const adv = finding.advisory
  const sf = finding.scannerFacts
  const cweNum = finding.cwe?.replace(/^CWE-/i, '')
  const allCves = Array.from(
    new Set([...(finding.cve ? [finding.cve] : []), ...(sf?.cveIds ?? [])])
  )
  const primaryCve = finding.cve && isCveId(finding.cve) ? finding.cve : null
  const { data: related } = useRelatedCVEs(primaryCve)
  const relatedCves = (related?.related_cves ?? []).filter((r) => !allCves.includes(r.cve_id))
  const v3 =
    sf?.cvssV3Vector || (finding.cvssVector?.startsWith('CVSS:3') ? finding.cvssVector : undefined)
  const v2 =
    sf?.cvssV2Vector ||
    (finding.cvssVector && !finding.cvssVector.startsWith('CVSS:') ? finding.cvssVector : undefined)
  const otherVector = finding.cvssVector && finding.cvssVector !== v3 && finding.cvssVector !== v2
  const port = sf?.networkPort
    ? `${sf.networkPort}${sf.networkTransport ? `/${sf.networkTransport}` : ''}${sf.networkService ? `, ${sf.networkService}` : ''}`
    : sf?.networkService
  const show =
    finding.cvss !== undefined ||
    finding.cvssVector ||
    finding.cve ||
    finding.cwe ||
    finding.owasp ||
    finding.epssScore !== undefined ||
    !!sf?.family ||
    sf?.vprScore !== undefined ||
    !!sf?.cvssV2Vector ||
    !!sf?.cvssV3Vector ||
    !!port
  if (!show) return null
  return (
    <DetailSection
      title={t('findings.overviewTab.identifiers', 'Identifiers and scores')}
      icon={Fingerprint}
    >
      <DetailFieldGrid>
        <DetailField label="CVSS">
          {finding.cvss !== undefined ? (
            <span className="tabular-nums">
              {finding.cvss.toFixed(1)}
              {sf?.cvssVersion && (
                <span className="text-muted-foreground">, v{sf.cvssVersion}</span>
              )}
            </span>
          ) : null}
        </DetailField>
        <DetailField label="EPSS">
          {finding.epssScore !== undefined ? (
            <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1 tabular-nums">
              <EpssChip
                score={finding.epssScore}
                threshold={0}
                digits={finding.epssScore < 0.1 ? 2 : 1}
              />
              {finding.epssPercentile !== undefined && (
                <span className="text-muted-foreground">
                  ,{' '}
                  {t('findings.overviewTab.percentile', '{value} percentile', {
                    value: formatEpssPercentile(finding.epssPercentile, 0),
                  })}
                </span>
              )}
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.vpr', 'Tenable VPR (input)')}>
          {sf?.vprScore !== undefined ? (
            <span
              className="tabular-nums"
              title={t(
                'findings.overviewTab.vprRefTitle',
                'Shown for reference; not used for the P0–P3 priority'
              )}
            >
              {sf.vprScore.toFixed(1)}
              <span className="text-muted-foreground">
                {' '}
                , {t('findings.overviewTab.notUsedForPriority', 'not used for priority')}
              </span>
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.family', 'Family')}>{sf?.family}</DetailField>
        <DetailField label={t('findings.overviewTab.cvssV3', 'CVSS v3 vector')} full>
          {v3 ? <Mono>{v3}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.cvssV2', 'CVSS v2 vector')} full>
          {v2 ? <Mono>{v2}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.cvssVec', 'CVSS vector')} full>
          {otherVector ? <Mono>{finding.cvssVector}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.port', 'Port')}>
          {port ? <Mono>{port}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.patchPublished', 'Patch published')}>
          {sf?.patchPublishedAt ? formatDay(sf.patchPublishedAt, locale) : null}
        </DetailField>
        <DetailField
          label={
            allCves.length > 1
              ? t('findings.overviewTab.cvesCount', 'CVEs ({count})', { count: allCves.length })
              : 'CVE'
          }
          full={allCves.length > 1}
        >
          {allCves.length > 0 ? (
            <span className="flex flex-wrap gap-x-3 gap-y-1" data-testid="finding-cves">
              {allCves.map((id) => (
                <CveLink key={id} id={id} />
              ))}
            </span>
          ) : null}
        </DetailField>
        <DetailField
          label={t('findings.overviewTab.relatedCves', 'Related CVEs (same assets)')}
          full
        >
          {relatedCves.length > 0 ? (
            <span className="flex flex-wrap gap-x-3 gap-y-1" data-testid="finding-related-cves">
              {relatedCves.slice(0, 12).map((r) => (
                <CveLink key={r.cve_id} id={r.cve_id} />
              ))}
              {relatedCves.length > 12 && (
                <span className="text-xs text-muted-foreground">
                  {t('findings.overviewTab.moreCount', '+{count} more', {
                    count: relatedCves.length - 12,
                  })}
                </span>
              )}
            </span>
          ) : null}
        </DetailField>
        <DetailField label="CWE">
          {finding.cwe && cweNum ? (
            <a
              href={`https://cwe.mitre.org/data/definitions/${encodeURIComponent(cweNum)}.html`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-mono text-[13px] text-primary hover:underline"
            >
              {finding.cwe}
              <ExternalLink className="h-3 w-3" aria-hidden />
            </a>
          ) : null}
        </DetailField>
        <DetailField label="OWASP">{finding.owasp}</DetailField>
        <DetailField label={t('findings.overviewTab.published', 'Published')}>
          {adv?.publishedAt
            ? new Date(adv.publishedAt).toLocaleDateString(locale, {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
              })
            : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.kev', 'CISA KEV')}>
          {adv?.kev ? (
            <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
              <KevBadge
                pastDue={adv.kev.isPastDue}
                ransomware={adv.kev.ransomwareUse === 'Known'}
              />
              <span>
                {t('findings.overviewTab.kevListed', 'Added {added}, due {due}', {
                  added: adv.kev.dateAdded.slice(0, 10),
                  due: adv.kev.dueDate.slice(0, 10),
                })}
              </span>
            </span>
          ) : adv ? (
            t('findings.overviewTab.notListed', 'Not listed')
          ) : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.references', 'References')} full>
          {adv && adv.references.length > 0 ? (
            <ul className="space-y-0.5">
              {adv.references.slice(0, 6).map((r) => (
                <li key={r.url} className="min-w-0">
                  <a
                    href={sanitizeExternalUrl(r.url)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex max-w-full items-center gap-1 text-primary hover:underline"
                  >
                    <span className="truncate">{r.url.replace(/^https?:\/\//, '')}</span>
                    <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                  </a>
                </li>
              ))}
            </ul>
          ) : null}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

/** File, lines and the code around them. */
/** How likely the model thinks the finding is a false positive (a suggestion). */
function AIFalsePositiveLikelihood({ data }: { data: AITriageSummaryData }) {
  if (data.falsePositiveLikelihood === undefined) return null
  return <span className="tabular-nums">{Math.round(data.falsePositiveLikelihood * 100)}%</span>
}

/** The latest completed AI triage. */
function AITriageSummary({ data }: { data: AITriageSummaryData }) {
  const { t, locale } = useTranslation()
  return (
    <DetailSection
      title={t('findings.overviewTab.aiAnalysis', 'AI analysis')}
      icon={Bot}
      actions={
        <span className="flex items-center gap-2 text-xs text-muted-foreground">
          <AIBadge source="ai_builtin" />
          {new Date(data.createdAt).toLocaleDateString(locale, {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
          })}
        </span>
      }
    >
      {data.recommendation && <p className="text-sm leading-relaxed">{data.recommendation}</p>}
      <DetailFieldGrid className="sm:grid-cols-3">
        <DetailField label={t('findings.overviewTab.riskScore', 'Risk score')}>
          {data.riskScore !== undefined ? (
            <span
              className={cn('tabular-nums', data.riskScore >= 70 && 'font-medium text-destructive')}
            >
              {data.riskScore} / 100
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.overviewTab.riskLevel', 'Risk level')}>
          {data.riskLevel ? (
            <span>{t(`findings.overviewTab.level.${data.riskLevel}`, data.riskLevel)}</span>
          ) : null}
        </DetailField>
        <DetailField
          label={t('findings.overviewTab.falsePositiveLikelihood', 'False-positive likelihood')}
        >
          <AIFalsePositiveLikelihood data={data} />
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}
