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

import { useCallback, useMemo, useState } from 'react'
import Link from '@/components/link'
import {
  ArrowUpRight,
  Bot,
  Check,
  Copy,
  ExternalLink,
  FileCode2,
  FileText,
  Fingerprint,
  Terminal,
  Server,
  ShieldAlert,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { MarkdownPreview } from '@/components/ui/markdown-editor'
import {
  DetailDisclosure,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
} from '@/features/shared/components/detail-sheet'
import { copyToClipboard } from '@/lib/clipboard'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import { useRelatedCVEs } from '../../api/use-finding-groups'
import { formatEpssPercentile, formatEpssScore } from '@/lib/epss'
import { cn, sanitizeExternalUrl } from '@/lib/utils'
import type { Activity, FindingDetail } from '../../types'
import { FINDING_TYPE_CONFIG } from '../../types'
import { CodeHighlighter } from './code-highlighter'
import { MetadataViewer } from './source-panels/metadata-viewer'
import { SourceDataSection } from './source-data-section'
import { VersionMatchPanel } from '@/features/vuln-matching/components/version-match-panel'
import { VERSION_MATCH_TOOL } from '@/features/vuln-matching/types'
import { findingTypeSections } from './finding-type-details'
import { assetDetailHref, isLinkableAssetId } from '../../lib/asset-link'
import { findingAssetTypeLabel } from '../../lib/finding-asset-type'
import { HUMAN_SOURCES, findingDescription } from '../../lib/finding-detail'
import { buildRepositoryCodeUrl } from '../../lib/repository-url'

interface OverviewTabProps {
  finding: FindingDetail
  /** Activities already loaded for the feed; the latest AI triage is read from them. */
  activities?: Activity[]
}

interface AITriageActivityData {
  riskScore?: number
  riskLevel?: string
  confidence?: string
  recommendation?: string
  createdAt: string
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[13px] break-all">{children}</span>
}

export function OverviewTab({ finding, activities = [] }: OverviewTabProps) {
  const isHuman = HUMAN_SOURCES.has(finding.source)

  const triage: AITriageActivityData | null = useMemo(() => {
    const latest = activities
      .filter((a) => a.type === 'ai_triage')
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]
    if (!latest?.metadata) return null
    const m = latest.metadata as Record<string, unknown>
    return {
      riskScore: m.risk_score as number | undefined,
      riskLevel: (m.ai_risk_level as string) || undefined,
      confidence: (m.ai_confidence as string) || undefined,
      recommendation: (m.ai_recommendation as string) || undefined,
      createdAt: latest.createdAt,
    }
  }, [activities])

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

      <DetailSection title="Description" icon={FileText}>
        {desc.text ? (
          isHuman ? (
            <MarkdownPreview content={desc.text} />
          ) : (
            <p className="text-sm leading-relaxed whitespace-pre-wrap">{desc.text}</p>
          )
        ) : (
          <p className="text-sm text-muted-foreground">The scanner sent no description.</p>
        )}
        {desc.fromAdvisory && adv?.cveId && (
          <p className="text-xs text-muted-foreground">From the {adv.cveId} advisory.</p>
        )}
      </DetailSection>

      {findingTypeSections(finding)}

      {(finding.filePath || finding.snippet || finding.contextSnippet) && (
        <CodeLocationSection finding={finding} />
      )}

      {finding.scannerOutput && <ScannerOutputSection output={finding.scannerOutput} />}

      {finding.toolName === VERSION_MATCH_TOOL && <VersionMatchPanel metadata={finding.metadata} />}

      {finding.sourceData && <SourceDataSection data={finding.sourceData} />}

      {extraAssets.length > 0 && (
        <DetailSection title="Targets" icon={Server} count={extraAssets.length}>
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
        <DetailSection title="Context" icon={ShieldAlert}>
          <DetailFieldGrid>
            <DetailField label="Attack vector">
              {finding.exposureVector && finding.exposureVector !== 'unknown' ? (
                <span className="capitalize">{finding.exposureVector}</span>
              ) : null}
            </DetailField>
            <DetailField label="Impact">
              {finding.impact ? <span className="capitalize">{finding.impact}</span> : null}
            </DetailField>
            <DetailField label="Likelihood">
              {finding.likelihood ? <span className="capitalize">{finding.likelihood}</span> : null}
            </DetailField>
            <DetailField label="Scanner confidence">
              {finding.confidence !== undefined ? `${finding.confidence}%` : null}
            </DetailField>
            <DetailField label="Data exposure">
              {finding.dataExposureRisk && finding.dataExposureRisk !== 'none' ? (
                <span className="capitalize">{finding.dataExposureRisk}</span>
              ) : null}
            </DetailField>
            <DetailField label="Reputational impact">
              {finding.reputationalImpact ? 'Yes' : null}
            </DetailField>
            <DetailField label="Prerequisites" full>
              {finding.attackPrerequisites}
            </DetailField>
            <DetailField label="Compliance impact" full>
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

      {!isHuman && (
        <DetailDisclosure summary="More details">
          <div className="mt-3 space-y-4">
            <DetailFieldGrid>
              <DetailField label="Rule">
                {finding.ruleId ? (
                  <span>
                    <Mono>{finding.ruleId}</Mono>
                    {finding.ruleName && finding.ruleName !== finding.ruleId && (
                      <span className="block text-muted-foreground">{finding.ruleName}</span>
                    )}
                  </span>
                ) : null}
              </DetailField>
              <DetailField label="Tool">
                {[finding.toolName, finding.toolVersion].filter(Boolean).join(' ') || null}
              </DetailField>
              <DetailField label="Finding type">{typeCfg?.label}</DetailField>
              <DetailField label="Classification">
                {finding.vulnerabilityClass?.length ? finding.vulnerabilityClass.join(', ') : null}
              </DetailField>
              <DetailField label="Remediation type">
                {finding.remediationType ? (
                  <span className="capitalize">{finding.remediationType}</span>
                ) : null}
              </DetailField>
              <DetailField label="Fix complexity">
                {finding.fixComplexity ? (
                  <span className="capitalize">{finding.fixComplexity}</span>
                ) : null}
              </DetailField>
              <DetailField label="Scan">
                {finding.scanId ? <Mono>{finding.scanId}</Mono> : null}
              </DetailField>
              <DetailField label="Recorded">
                {new Date(finding.createdAt).toLocaleString('en-US', {
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

const CVE_RE = /^CVE-\d{4}-\d{4,}$/

/** A CVE id as an NVD link, or as text when it is not a well-formed CVE id. */
function CveLink({ id }: { id: string }) {
  if (!CVE_RE.test(id)) return <Mono>{id}</Mono>
  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 font-mono text-[13px] text-primary hover:underline"
    >
      {id}
      <ExternalLink className="h-3 w-3" aria-hidden />
    </a>
  )
}

function formatDay(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
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
  return (
    <DetailSection title="Scanner output" icon={Terminal}>
      <p className="text-xs text-muted-foreground">
        What the scanner printed as its proof
        {output.updatedAt && <> · from the sighting of {formatDay(output.updatedAt)}</>}
        {output.truncated && <> · cut at 64 KiB</>}. Shown as plain text.
      </p>
      <DetailDisclosure summary="Show output">
        <UntrustedTextBlock className="mt-2" text={output.text} label="Scanner output" />
      </DetailDisclosure>
    </DetailSection>
  )
}

function IdentifiersSection({ finding }: { finding: FindingDetail }) {
  const adv = finding.advisory
  const sf = finding.scannerFacts
  const cweNum = finding.cwe?.replace(/^CWE-/i, '')
  const allCves = Array.from(
    new Set([...(finding.cve ? [finding.cve] : []), ...(sf?.cveIds ?? [])])
  )
  const primaryCve = finding.cve && CVE_RE.test(finding.cve) ? finding.cve : null
  const { data: related } = useRelatedCVEs(primaryCve)
  const relatedCves = (related?.related_cves ?? []).filter((r) => !allCves.includes(r.cve_id))
  const v3 =
    sf?.cvssV3Vector || (finding.cvssVector?.startsWith('CVSS:3') ? finding.cvssVector : undefined)
  const v2 =
    sf?.cvssV2Vector ||
    (finding.cvssVector && !finding.cvssVector.startsWith('CVSS:') ? finding.cvssVector : undefined)
  const otherVector = finding.cvssVector && finding.cvssVector !== v3 && finding.cvssVector !== v2
  const port = sf?.networkPort
    ? `${sf.networkPort}${sf.networkTransport ? `/${sf.networkTransport}` : ''}${sf.networkService ? ` · ${sf.networkService}` : ''}`
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
    <DetailSection title="Identifiers and scores" icon={Fingerprint}>
      <DetailFieldGrid>
        <DetailField label="CVSS">
          {finding.cvss !== undefined ? (
            <span className="tabular-nums">
              {finding.cvss.toFixed(1)}
              {sf?.cvssVersion && (
                <span className="text-muted-foreground"> · v{sf.cvssVersion}</span>
              )}
            </span>
          ) : null}
        </DetailField>
        <DetailField label="EPSS">
          {finding.epssScore !== undefined ? (
            <span className="tabular-nums">
              {formatEpssScore(finding.epssScore, finding.epssScore < 0.1 ? 2 : 1)}
              {finding.epssPercentile !== undefined && (
                <span className="text-muted-foreground">
                  {' '}
                  · {formatEpssPercentile(finding.epssPercentile, 0)} percentile
                </span>
              )}
            </span>
          ) : null}
        </DetailField>
        <DetailField label="Tenable VPR (input)">
          {sf?.vprScore !== undefined ? (
            <span
              className="tabular-nums"
              title="Shown for reference; not used for the P0–P3 priority"
            >
              {sf.vprScore.toFixed(1)}
              <span className="text-muted-foreground"> · not used for priority</span>
            </span>
          ) : null}
        </DetailField>
        <DetailField label="Family">{sf?.family}</DetailField>
        <DetailField label="CVSS v3 vector" full>
          {v3 ? <Mono>{v3}</Mono> : null}
        </DetailField>
        <DetailField label="CVSS v2 vector" full>
          {v2 ? <Mono>{v2}</Mono> : null}
        </DetailField>
        <DetailField label="CVSS vector" full>
          {otherVector ? <Mono>{finding.cvssVector}</Mono> : null}
        </DetailField>
        <DetailField label="Port">{port ? <Mono>{port}</Mono> : null}</DetailField>
        <DetailField label="Patch published">
          {sf?.patchPublishedAt ? formatDay(sf.patchPublishedAt) : null}
        </DetailField>
        <DetailField
          label={allCves.length > 1 ? `CVEs (${allCves.length})` : 'CVE'}
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
        <DetailField label="Related CVEs (same assets)" full>
          {relatedCves.length > 0 ? (
            <span className="flex flex-wrap gap-x-3 gap-y-1" data-testid="finding-related-cves">
              {relatedCves.slice(0, 12).map((r) => (
                <CveLink key={r.cve_id} id={r.cve_id} />
              ))}
              {relatedCves.length > 12 && (
                <span className="text-xs text-muted-foreground">
                  +{relatedCves.length - 12} more
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
        <DetailField label="Published">
          {adv?.publishedAt
            ? new Date(adv.publishedAt).toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
              })
            : null}
        </DetailField>
        <DetailField label="CISA KEV">
          {adv?.kev ? (
            <span className="font-medium text-destructive">
              Added {adv.kev.dateAdded.slice(0, 10)} · due {adv.kev.dueDate.slice(0, 10)}
              {adv.kev.ransomwareUse === 'Known' && ' · used by ransomware'}
            </span>
          ) : adv ? (
            'Not listed'
          ) : null}
        </DetailField>
        <DetailField label="References" full>
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
function CodeLocationSection({ finding }: { finding: FindingDetail }) {
  const [copied, setCopied] = useState(false)
  const code = finding.contextSnippet || finding.snippet
  const startLine = finding.contextSnippet ? finding.contextStartLine || 1 : finding.startLine || 1
  const lines =
    finding.startLine !== undefined && finding.startLine > 0
      ? `${finding.startLine}${finding.endLine && finding.endLine !== finding.startLine ? `–${finding.endLine}` : ''}`
      : ''
  const repoUrl = buildRepositoryCodeUrl({
    repositoryUrl: finding.repositoryUrl || finding.assets[0]?.url,
    filePath: finding.filePath,
    startLine: finding.startLine,
    endLine: finding.endLine,
    branch: finding.branch,
    commitSha: finding.commitSha,
  })

  const copy = useCallback(async () => {
    if (code && (await copyToClipboard(code))) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
  }, [code])

  return (
    <DetailSection
      title="Code location"
      icon={FileCode2}
      actions={
        repoUrl ? (
          <a
            href={sanitizeExternalUrl(repoUrl)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
          >
            View in repository
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        ) : undefined
      }
    >
      {finding.filePath && (
        <p className="font-mono text-[13px] break-all">
          {finding.filePath}
          {lines && <span className="text-muted-foreground">:{lines}</span>}
        </p>
      )}
      {(finding.branch || finding.commitSha) && (
        <p className="text-xs text-muted-foreground">
          {finding.branch && (
            <>
              Branch <span className="font-mono">{finding.branch}</span>
            </>
          )}
          {finding.branch && finding.commitSha && ' · '}
          {finding.commitSha && (
            <>
              Commit <span className="font-mono">{finding.commitSha.slice(0, 10)}</span>
            </>
          )}
        </p>
      )}
      {code && (
        <div className="overflow-hidden rounded-lg border bg-muted/30">
          <div className="flex items-center justify-between border-b bg-muted/50 px-3 py-1.5">
            <span className="text-xs text-muted-foreground">
              {finding.contextSnippet ? 'Snippet with context' : 'Snippet'}
            </span>
            <button
              type="button"
              onClick={() => void copy()}
              className="rounded-sm p-1 text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              aria-label="Copy code"
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>
          <div className="overflow-x-auto p-3">
            <CodeHighlighter
              code={code}
              filePath={finding.filePath}
              className="bg-transparent"
              showLineNumbers
              startLine={startLine}
              highlightLine={finding.startLine}
            />
          </div>
        </div>
      )}
    </DetailSection>
  )
}

/** The latest AI triage, read from the activity feed (no extra request). */
function AITriageSummary({ data }: { data: AITriageActivityData }) {
  return (
    <DetailSection
      title="AI analysis"
      icon={Bot}
      actions={
        <span className="text-xs text-muted-foreground">
          {new Date(data.createdAt).toLocaleDateString('en-US', {
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
        <DetailField label="Risk score">
          {data.riskScore !== undefined ? (
            <span
              className={cn('tabular-nums', data.riskScore >= 70 && 'font-medium text-destructive')}
            >
              {data.riskScore} / 100
            </span>
          ) : null}
        </DetailField>
        <DetailField label="Risk level">
          {data.riskLevel ? <span className="capitalize">{data.riskLevel}</span> : null}
        </DetailField>
        <DetailField label="Confidence">
          {data.confidence ? <span className="capitalize">{data.confidence}</span> : null}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}
