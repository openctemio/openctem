'use client'

/**
 * The centre of triage mode: what the finding is, how sure we are it is
 * still there, and the four facts a decision rests on (asset, exploitation,
 * SLA, owner), then its evidence. Every value from the finding is untrusted
 * text and rendered as text. Evidence shows the masked snippet the finding
 * carries; the tool's evidence items load only when asked for (`e`), so
 * moving to the next finding costs one read.
 * Design: research/234 §5.2.
 */

import { useTranslation } from '@/context/i18n-provider'
import { SeverityBadge } from '@/features/shared'
import type { Severity } from '@/features/shared/types'
import { SlaStatusBadge } from '@/features/sla/components/sla-status-badge'
import { formatRelativeTime } from '@/lib/format-metric'
import { toDisplayText } from '@/lib/untrusted-text'
import { Skeleton } from '@/components/ui/skeleton'
import type { ApiFinding } from '../../api/finding-api.types'
import { useFindingEvidenceItems } from '../../api/use-finding-evidence-items'
import { displayTitle } from '../../lib/finding-display'
import { findingDescription, toFindingDetail } from '../../lib/finding-detail'
import { ExploitSignals } from '../exploit-signals'
import { PriorityClassBadge } from '../priority-class-badge'
import { FindingStatusBadge } from '../finding-status-badge'
import { FindingEvidenceItems } from '../detail/finding-evidence-items'

/** Multi-line untrusted text: each line made safe on its own, the breaks kept. */
function displayLines(value: string, max: number): string {
  return value
    .slice(0, max)
    .split(/\r?\n/)
    .map((line) => toDisplayText(line, max))
    .join('\n')
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  )
}

export function TriageFindingSkeleton() {
  return (
    <div className="space-y-4" aria-busy data-testid="triage-finding-loading">
      <Skeleton className="h-5 w-64" />
      <Skeleton className="h-7 w-3/4" />
      <Skeleton className="h-4 w-1/2" />
      <Skeleton className="h-20 w-full rounded-lg" />
      <Skeleton className="h-32 w-full rounded-lg" />
    </div>
  )
}

export function TriageFindingView({
  finding,
  showEvidence,
  note,
  advisory,
}: {
  finding: ApiFinding
  showEvidence: boolean
  /** The AI suggestion card, under the evidence. */
  advisory?: React.ReactNode
  /** A notice about this finding (changed by someone else, pending approval). */
  note?: React.ReactNode
}) {
  const { t, locale } = useTranslation()
  const detail = toFindingDetail(finding)
  const title = toDisplayText(displayTitle(detail, t) || finding.rule_id || finding.id, 500)
  const desc = findingDescription(detail).text
  const asset = finding.asset
  const lastSeen = finding.last_seen_at
  const firstSeen = finding.first_detected_at || finding.created_at
  const tool = finding.last_seen_tool || finding.tool_name
  const snippet = finding.snippet || finding.context_snippet
  const { data: evidence, isLoading: evidenceLoading } = useFindingEvidenceItems(
    showEvidence ? finding.id : null
  )
  const evidenceItems = evidence?.data ?? []

  return (
    <article className="min-w-0 space-y-4" aria-labelledby="triage-finding-title">
      <div className="flex flex-wrap items-center gap-1.5">
        <PriorityClassBadge
          priorityClass={finding.priority_class}
          showWord
          assetId={finding.asset_id}
        />
        {typeof finding.rank === 'number' && (
          <span className="font-mono text-xs text-muted-foreground tabular-nums">
            {t('findings.triageMode.rank', 'rank {rank}', { rank: Math.round(finding.rank) })}
          </span>
        )}
        <SeverityBadge severity={finding.severity as Severity} />
        <FindingStatusBadge status={finding.status} />
        <ExploitSignals
          isInKev={finding.is_in_kev}
          kevDueDate={finding.kev_due_date}
          kevRansomware={finding.kev_ransomware}
          epssScore={finding.epss_score}
        />
        {finding.cve_id && (
          <span className="rounded border px-1.5 py-0.5 font-mono text-xs">
            {toDisplayText(finding.cve_id, 40)}
          </span>
        )}
        {(finding.cwe_ids ?? []).slice(0, 3).map((cwe) => (
          <span key={cwe} className="rounded border px-1.5 py-0.5 font-mono text-xs">
            {toDisplayText(cwe, 20)}
          </span>
        ))}
        {tool && (
          <span className="rounded border px-1.5 py-0.5 text-xs text-muted-foreground">
            {t('findings.triageMode.foundBy', 'Found by {tool}', { tool: toDisplayText(tool, 60) })}
          </span>
        )}
      </div>

      <h2
        id="triage-finding-title"
        dir="auto"
        className="text-xl font-semibold tracking-tight [unicode-bidi:isolate]"
      >
        {title}
      </h2>

      <p className="text-sm text-muted-foreground">
        {lastSeen
          ? t('findings.triageMode.lastSeen', 'Last seen {when}. First seen {first}.', {
              when: formatRelativeTime(lastSeen, locale),
              first: formatRelativeTime(firstSeen, locale),
            })
          : t('findings.triageMode.firstSeen', 'First seen {first}.', {
              first: formatRelativeTime(firstSeen, locale),
            })}
      </p>

      {note}

      <dl className="grid grid-cols-2 gap-4 rounded-lg border bg-card p-4 md:grid-cols-4">
        <Fact label={t('findings.triageMode.fact.asset', 'Asset')}>
          {asset?.name ? (
            <span className="flex min-w-0 flex-wrap items-center gap-1.5">
              <span dir="auto" className="truncate font-medium [unicode-bidi:isolate]">
                {toDisplayText(asset.name, 200)}
              </span>
              {asset.is_internet_accessible && (
                <span className="rounded border px-1 font-mono text-xs font-semibold">
                  {t('findings.triageMode.internet', 'NET')}
                </span>
              )}
              {asset.criticality && (
                <span className="text-xs text-muted-foreground">
                  {t(`criticality.${asset.criticality}`, asset.criticality)}
                </span>
              )}
            </span>
          ) : (
            <span className="text-muted-foreground">
              {t('findings.triageMode.noAsset', 'No asset')}
            </span>
          )}
        </Fact>
        <Fact label={t('findings.triageMode.fact.exploitation', 'Exploitation')}>
          {finding.is_in_kev || typeof finding.epss_score === 'number' ? (
            <span className="flex flex-wrap items-center gap-1.5">
              {typeof finding.epss_score === 'number' && (
                <span className="font-mono tabular-nums">
                  {t('findings.triageMode.epss', 'EPSS {value}%', {
                    value: Math.round(finding.epss_score * 1000) / 10,
                  })}
                </span>
              )}
              {finding.is_in_kev && (
                <span className="rounded border px-1 font-mono text-xs font-semibold">
                  {t('findings.triageMode.kev', 'KEV')}
                </span>
              )}
            </span>
          ) : (
            <span className="text-muted-foreground">
              {t('findings.triageMode.noSignal', 'No signal')}
            </span>
          )}
        </Fact>
        <Fact label={t('findings.triageMode.fact.sla', 'SLA')}>
          <span className="flex flex-wrap items-center gap-1.5">
            <SlaStatusBadge status={finding.sla_status} />
            {finding.sla_deadline && (
              <span className="text-xs text-muted-foreground">
                {formatRelativeTime(finding.sla_deadline, locale)}
              </span>
            )}
          </span>
        </Fact>
        <Fact label={t('findings.triageMode.fact.owner', 'Owner')}>
          {finding.assigned_to_user?.name || finding.assigned_to_user?.email ? (
            <span dir="auto" className="truncate [unicode-bidi:isolate]">
              {toDisplayText(
                finding.assigned_to_user?.name || finding.assigned_to_user?.email,
                120
              )}
            </span>
          ) : (
            <span className="text-muted-foreground">
              {t('findings.triageMode.unassigned', 'Unassigned')}
            </span>
          )}
        </Fact>
      </dl>

      {desc && (
        <p dir="auto" className="line-clamp-4 text-sm whitespace-pre-line [unicode-bidi:isolate]">
          {displayLines(desc, 2000)}
        </p>
      )}

      <section
        aria-labelledby="triage-evidence-title"
        className="space-y-2 rounded-lg border bg-card p-4"
      >
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h3 id="triage-evidence-title" className="text-sm font-medium">
            {t('findings.triageMode.evidence', 'Evidence')}
          </h3>
          <span className="text-xs text-muted-foreground">
            {t(
              'findings.triageMode.evidenceMasked',
              'Values are masked. Revealing one needs permission and is audited.'
            )}
          </span>
        </div>
        {snippet ? (
          <pre className="max-h-64 overflow-auto rounded bg-muted p-3 font-mono text-xs whitespace-pre-wrap">
            {displayLines(snippet, 4000)}
          </pre>
        ) : (
          !showEvidence && (
            <p className="text-sm text-muted-foreground">
              {t('findings.triageMode.noSnippet', 'No snippet on this finding.')}
            </p>
          )
        )}
        {showEvidence &&
          (evidenceLoading ? (
            <Skeleton className="h-16 w-full" />
          ) : evidenceItems.length > 0 ? (
            <FindingEvidenceItems findingId={finding.id} items={evidenceItems} />
          ) : (
            <p className="text-sm text-muted-foreground">
              {t('findings.triageMode.noEvidenceItems', 'The tools attached no evidence items.')}
            </p>
          ))}
      </section>
      {advisory}
    </article>
  )
}
