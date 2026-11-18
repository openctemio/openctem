'use client'

/**
 * The finding's properties (who, when and where) as a
 * label → value list in the page's right rail (and in the drawer). Status,
 * severity and assignee are editable in place through `useFindingTriage`.
 *
 * Read top to bottom: state (status, severity, priority, assignee, SLA), then
 * where (asset, source), then when (first / last seen), then trivia.
 */

import { SlaWhyThisDate } from './sla-why-this-date'
import { assigneeLabel } from '../../lib/assignee-label'
import { VERSION_MATCH_TOOL } from '@/features/vuln-matching/types'
import { findingStatusesInCategory } from '@/features/findings/types/finding.types'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { ArrowUpRight } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { DetailCopyId } from '@/features/shared/components/detail-sheet'
import {
  PropertyFold,
  PropertyGroup,
  PropertyList,
  PropertyRow,
} from '@/features/shared/components/detail'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { daysUntil, isBreach } from '@/features/sla/lib/sla'
import { cn } from '@/lib/utils'
import type { FindingDetail } from '../../types'
import type { FindingTriage } from '../../hooks/use-finding-triage'
import { StatusSelect } from '../status-select'
import { FindingTicketLinks } from './finding-ticket-links'
import { SeveritySelect } from '../severity-select'
import { SeverityProvenance } from './severity-provenance'
import { useCanMutate } from '@/lib/permissions'
import { AssigneeSelect } from '../assignee-select'
import { FindingPeople } from './finding-people'
import { PriorityClassBadge } from '../priority-class-badge'
import { findingAssetTypeLabel } from '../../lib/finding-asset-type'
import { userTags } from '../../lib/finding-display'
import { assetDetailHref, isLinkableAssetId } from '../../lib/asset-link'
import { findingDetailHref } from '../../lib/finding-link'
import { findingSourceText, isTriageLocked } from '../../lib/finding-detail'
import { closureReasonLabel, verificationLabel } from '../../lib/closure'
import { CRITICALITY_LABELS } from '@/lib/criticality'
import { formatDate as localeFormatDate } from '@/lib/app-locale'

const CLOSED = new Set<string>(findingStatusesInCategory('closed'))

function formatDate(iso: string | undefined, _locale: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d.getTime())) return ''
  return localeFormatDate(d, { month: 'short', day: 'numeric', year: 'numeric' })
}

/** "May 12, 2026 · 143 days overdue" with the overdue part in the destructive colour. */
export function SlaDue({
  deadline,
  status,
  closed,
  kevCapped,
}: {
  deadline?: string
  status?: string
  closed?: boolean
  /** The SLA policy's known exploited (KEV) cap shortened the deadline. */
  kevCapped?: boolean
}) {
  const { t, locale } = useTranslation()
  if (!deadline)
    return <span className="text-muted-foreground">{t('findings.properties.noSla', 'No SLA')}</span>
  const days = daysUntil(deadline)
  const late = days !== null && days < 0
  const rel =
    days === null
      ? ''
      : days === 0
        ? t('findings.properties.dueToday', 'due today')
        : late
          ? Math.abs(days) === 1
            ? t('findings.properties.overdueOne', '{count} day overdue', { count: 1 })
            : t('findings.properties.overdueMany', '{count} days overdue', {
                count: Math.abs(days),
              })
          : days === 1
            ? t('findings.properties.leftOne', '{count} day left', { count: 1 })
            : t('findings.properties.leftMany', '{count} days left', { count: days })
  return (
    <span>
      <span className="tabular-nums">{formatDate(deadline, locale)}</span>
      {rel && !closed && (
        <span
          className={cn(
            'block text-xs tabular-nums',
            late || isBreach(status) ? 'font-medium text-destructive' : 'text-muted-foreground',
            !late && status === 'warning' && 'text-warning'
          )}
        >
          {rel}
        </span>
      )}
      {kevCapped && (
        <span data-slot="sla-kev-capped" className="block text-xs text-muted-foreground">
          {t('findings.properties.slaKevCapped', 'Shortened because it is in CISA KEV')}
        </span>
      )}
    </span>
  )
}

/**
 * A closed finding's state row, in place of the SLA countdown: the words of
 * its closed status and the day it was closed. An accepted risk says until
 * when (the day the finding reopens); a duplicate links the finding it
 * duplicates.
 */
export function ClosedStateRow({ finding, status }: { finding: FindingDetail; status: string }) {
  const { t, locale } = useTranslation()
  const closedOn = formatDate(finding.resolvedAt, locale)
  const on = closedOn ? (
    <span className="block text-xs text-muted-foreground tabular-nums">
      {t('findings.properties.closedOn', 'On {date}', { date: closedOn })}
    </span>
  ) : null

  if (status === 'accepted') {
    const until = formatDate(finding.acceptanceExpiresAt, locale)
    return (
      <PropertyRow label={t('findings.properties.riskAccepted', 'Risk accepted')}>
        <span data-slot="finding-closed-state">
          {until ? (
            <span className="tabular-nums">
              {t('findings.properties.acceptedUntil', 'Until {date}', { date: until })}
            </span>
          ) : (
            <span className="text-muted-foreground">
              {t('findings.properties.acceptedNoEnd', 'No end date')}
            </span>
          )}
          {on}
        </span>
      </PropertyRow>
    )
  }
  if (status === 'duplicate') {
    return (
      <PropertyRow label={t('findings.properties.duplicateOf', 'Duplicate of')}>
        <span data-slot="finding-closed-state">
          {finding.duplicateOf ? (
            <Link
              href={findingDetailHref(finding.duplicateOf)}
              className="rounded-sm font-medium hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              {t('findings.properties.originalFinding', 'The original finding')}
              <ArrowUpRight className="ms-0.5 inline h-3.5 w-3.5 align-text-top" aria-hidden />
            </Link>
          ) : (
            <span className="text-muted-foreground">
              {t('findings.properties.originalUnknown', 'Original not recorded')}
            </span>
          )}
          {on}
        </span>
      </PropertyRow>
    )
  }
  const label =
    status === 'false_positive'
      ? t('findings.properties.markedFalsePositive', 'Marked false positive')
      : status === 'resolved'
        ? t('findings.properties.resolved', 'Resolved')
        : t('findings.properties.closed', 'Closed')
  return (
    <PropertyRow label={label}>
      <span data-slot="finding-closed-state" className="tabular-nums">
        {closedOn || <span className="text-muted-foreground">-</span>}
      </span>
    </PropertyRow>
  )
}

export interface FindingPropertiesProps {
  finding: FindingDetail
  triage: FindingTriage
  /** Hide the edit controls (e.g. pentest findings are managed in the campaign). */
  readOnly?: boolean
  /**
   * The drawer: leave out status, severity and assignee (edited in its header
   * row), the priority (the "Why it matters" card leads with it) and the ID
   * (in its menu).
   */
  hideTriage?: boolean
  className?: string
}

export function FindingProperties({
  finding,
  triage,
  readOnly,
  hideTriage,
  className,
}: FindingPropertiesProps) {
  const { t, locale } = useTranslation()
  const locked = isTriageLocked(finding.source, readOnly)
  // Re-scoring needs findings:severity, which a remediation owner may lack.
  const canRescore = useCanMutate('PATCH /api/v1/findings/{id}/severity')
  const canAssign = useCanMutate('POST /api/v1/findings/{id}/assign')
  const asset = finding.assets[0]
  const crit = asset?.criticality
  // Type, criticality and exposure as separate muted pieces (no middot join).
  const assetCaptionParts: string[] = asset
    ? [
        findingAssetTypeLabel(asset.type),
        crit === 'critical'
          ? t('findings.properties.criticalAsset', 'Critical asset')
          : crit === 'none'
            ? t('findings.properties.critNotRated', 'Criticality not rated')
            : crit
              ? t('findings.properties.critLevel', '{level} criticality', {
                  level: CRITICALITY_LABELS[crit],
                })
              : null,
        asset.exposure && asset.exposure !== 'unknown'
          ? asset.exposure.charAt(0).toUpperCase() + asset.exposure.slice(1)
          : null,
      ].filter((part): part is string => Boolean(part))
    : []
  const closed = CLOSED.has(triage.status)
  // People's labels only; scanner artefacts (tool, file, type) are noise here.
  const tags = userTags(finding)
  // A version-based match has no scanning tool behind it (RFC-066).
  const tool =
    finding.toolName === VERSION_MATCH_TOOL
      ? t('findings.properties.versionMatch', 'Version match')
      : [finding.toolName, finding.toolVersion].filter(Boolean).join(' ')

  const assigneeNode = hideTriage ? (
    <span className={triage.assignee ? undefined : 'text-muted-foreground'}>
      {assigneeLabel(triage.assignee, {
        assigned: t('findings.assigneeSelect.assigned', 'Assigned'),
        unassigned: t('findings.properties.unassigned', 'Unassigned'),
      })}
    </span>
  ) : (
    <AssigneeSelect
      findingId={finding.id}
      disabled={locked || !canAssign}
      value={
        triage.assignee
          ? {
              id: triage.assignee.id,
              name: triage.assignee.name,
              email: triage.assignee.email,
              role: triage.assignee.role,
            }
          : null
      }
      onChange={(u) =>
        triage.changeAssignee(
          u ? { id: u.id, name: u.name, email: u.email || '', role: 'analyst' } : null
        )
      }
      loading={triage.assigneeBusy}
      variant="ghost"
      showFullName
      placeholder={t('findings.properties.unassigned', 'Unassigned')}
    />
  )

  return (
    <PropertyList label={t('findings.properties.ariaLabel', 'Properties')} className={className}>
      <PropertyGroup>
        {!hideTriage && (
          <>
            <PropertyRow label={t('findings.properties.status', 'Status')}>
              <StatusSelect
                findingId={finding.id}
                value={triage.status}
                subStatusId={triage.subStatusId}
                allowSubStatusMoves
                onChange={triage.changeStatus}
                loading={triage.statusBusy}
                disabled={locked}
              />
            </PropertyRow>
            <PropertyRow label={t('findings.properties.severity', 'Severity')}>
              <SeveritySelect
                value={triage.severity}
                onChange={triage.changeSeverity}
                loading={triage.severityBusy}
                disabled={locked || !canRescore || !!finding.pendingSeverityRequest}
                cvss={finding.cvss}
                showIcon={false}
              />
              <SeverityProvenance
                finding={finding}
                canRescore={!locked && canRescore}
                onRestore={triage.restoreSeverity}
              />
            </PropertyRow>
          </>
        )}
        {!hideTriage && (
          <PropertyRow label={t('findings.properties.priority', 'Priority')}>
            {finding.priorityClass ? (
              <span className="inline-flex items-center gap-1.5">
                <PriorityClassBadge priorityClass={finding.priorityClass} showWord />
                {finding.priorityClassOverride && (
                  <span className="text-xs text-muted-foreground">
                    {t('findings.properties.setManually', 'set manually')}
                  </span>
                )}
              </span>
            ) : (
              <span className="text-muted-foreground">
                {t('findings.properties.notClassified', 'Not classified')}
              </span>
            )}
          </PropertyRow>
        )}
        {closed ? (
          <ClosedStateRow finding={finding} status={triage.status} />
        ) : (
          <PropertyRow label={t('findings.properties.slaDue', 'SLA due')}>
            <div className="flex flex-col items-start gap-0.5">
              <SlaDue
                deadline={finding.slaDeadline}
                status={finding.slaStatus}
                kevCapped={finding.slaKevCapped}
              />
              <SlaWhyThisDate
                basis={finding.slaBasis}
                priorityClass={finding.priorityClass}
                severity={finding.severity}
              />
            </div>
          </PropertyRow>
        )}
      </PropertyGroup>
      <FindingPeople findingId={finding.id} assignee={assigneeNode} />

      {/* Phone: the state rows stay visible, the rest is one tap away. */}
      <PropertyFold
        label={t('findings.properties.moreDetails', 'Asset, dates and more')}
        openLabel={t('findings.properties.fewerDetails', 'Fewer details')}
      >
        <PropertyGroup>
          {asset && (
            <PropertyRow label={t('findings.properties.asset', 'Asset')}>
              <span className="block min-w-0">
                {isLinkableAssetId(asset.id) ? (
                  <Link
                    href={assetDetailHref(asset.id)}
                    className="rounded-sm font-medium break-words hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                  >
                    {asset.name}
                    <ArrowUpRight
                      className="ms-0.5 inline h-3.5 w-3.5 align-text-top"
                      aria-hidden
                    />
                  </Link>
                ) : (
                  <span className="font-medium">{asset.name}</span>
                )}
                {assetCaptionParts.length > 0 && (
                  <span
                    data-slot="asset-caption"
                    className="flex flex-wrap gap-x-2 text-xs text-muted-foreground"
                  >
                    {assetCaptionParts.map((part) => (
                      <span key={part}>{part}</span>
                    ))}
                  </span>
                )}
                {finding.assets.length > 1 && (
                  <span className="block text-xs text-muted-foreground">
                    {t('findings.properties.moreAssets', '+{count} more', {
                      count: finding.assets.length - 1,
                    })}
                  </span>
                )}
              </span>
            </PropertyRow>
          )}
          <PropertyRow label={t('findings.properties.foundBy', 'Found by')}>
            <span>
              {findingSourceText(t, finding.source)}
              {tool && <span className="block text-xs text-muted-foreground">{tool}</span>}
            </span>
          </PropertyRow>
          <PropertyRow label={t('findings.properties.firstSeen', 'First seen')}>
            <span title={finding.discoveredAt}>
              <span className="tabular-nums">{formatDate(finding.discoveredAt, locale)}</span>
              <span className="block text-xs text-muted-foreground">
                <RelativeTime date={finding.discoveredAt} />
              </span>
            </span>
          </PropertyRow>
          {finding.lastSeenAt &&
            finding.lastSeenAt.slice(0, 10) !== finding.discoveredAt.slice(0, 10) && (
              <PropertyRow label={t('findings.properties.lastSeen', 'Last seen')}>
                <span className="tabular-nums" title={finding.lastSeenAt}>
                  {formatDate(finding.lastSeenAt, locale)}
                </span>
              </PropertyRow>
            )}
          {(finding.occurrenceCount ?? 0) > 1 && (
            <PropertyRow label={t('findings.properties.seenIn', 'Seen in')}>
              <span className="tabular-nums">
                {t('findings.properties.scansCount', '{count} scans', {
                  count: finding.occurrenceCount ?? 0,
                })}
              </span>
            </PropertyRow>
          )}
          {finding.observation === 'stale' && (
            <PropertyRow label={t('findings.properties.observation', 'Observation')}>
              <span>
                {t('findings.observation.stale', 'Stale: not reported lately, not fixed')}
              </span>
            </PropertyRow>
          )}
          {finding.validation && (
            <PropertyRow label={t('findings.properties.validation', 'Validation')}>
              <span>
                {finding.validation === 'not_reproducible'
                  ? t('findings.validation.not_reproducible', 'Not reproducible')
                  : t('findings.validation.reproducible', 'Reproducible')}
              </span>
            </PropertyRow>
          )}
          {finding.closureReason && (
            <PropertyRow label={t('findings.properties.closedAs', 'Closed as')}>
              <span className="inline-flex flex-wrap gap-x-2">
                <span>{closureReasonLabel(t, finding.closureReason)}</span>
                {finding.verification && (
                  <span className="text-muted-foreground">
                    {verificationLabel(t, finding.verification)}
                  </span>
                )}
              </span>
            </PropertyRow>
          )}
          <PropertyRow label={t('findings.properties.tickets', 'Tickets')}>
            <FindingTicketLinks findingId={finding.id} workItemUris={finding.workItemUris} />
          </PropertyRow>
          {tags.length > 0 && (
            <PropertyRow label={t('findings.properties.tags', 'Tags')}>
              <span className="flex flex-wrap gap-1 py-1">
                {tags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="text-xs font-normal">
                    {tag}
                  </Badge>
                ))}
              </span>
            </PropertyRow>
          )}
          {!hideTriage && (
            <PropertyRow label={t('findings.properties.id', 'ID')}>
              <DetailCopyId
                id={finding.id}
                label={t('findings.properties.findingId', 'Finding ID')}
              />
            </PropertyRow>
          )}
        </PropertyGroup>
      </PropertyFold>
    </PropertyList>
  )
}
