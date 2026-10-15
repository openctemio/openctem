'use client'

/**
 * The finding's properties (who, when and where) as a
 * label → value list in the page's right rail (and in the drawer). Status,
 * severity and assignee are editable in place through `useFindingTriage`.
 *
 * Read top to bottom: state (status, severity, priority, assignee, SLA), then
 * where (asset, source), then when (first / last seen), then trivia.
 */

import { VERSION_MATCH_TOOL } from '@/features/vuln-matching/types'
import { findingStatusesInCategory } from '@/features/findings/types/finding.types'
import Link from '@/components/link'
import { useId, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { ArrowUpRight, ChevronRight, ExternalLink } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { DetailCopyId } from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { daysUntil, isBreach } from '@/features/sla/lib/sla'
import { cn, sanitizeExternalUrl } from '@/lib/utils'
import type { FindingDetail } from '../../types'
import type { FindingTriage } from '../../hooks/use-finding-triage'
import { StatusSelect } from '../status-select'
import { SeveritySelect } from '../severity-select'
import { useCanMutate } from '@/lib/permissions'
import { AssigneeSelect } from '../assignee-select'
import { PriorityClassBadge } from '../priority-class-badge'
import { findingAssetTypeLabel } from '../../lib/finding-asset-type'
import { userTags } from '../../lib/finding-display'
import { assetDetailHref, isLinkableAssetId } from '../../lib/asset-link'
import { findingSourceLabel, HUMAN_SOURCES } from '../../lib/finding-detail'
import { closureReasonLabel, verificationLabel } from '../../lib/closure'
import { CRITICALITY_LABELS } from '@/lib/criticality'

const CLOSED = new Set<string>(findingStatusesInCategory('closed'))

function formatDate(iso?: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d.getTime())) return ''
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  if (children === null || children === undefined || children === false || children === '')
    return null
  return (
    <div className="grid min-h-8 grid-cols-[6.5rem_minmax(0,1fr)] items-center gap-x-3">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm break-words">{children}</dd>
    </div>
  )
}

/** "May 12, 2026 · 143 days overdue" with the overdue part in the destructive colour. */
export function SlaDue({
  deadline,
  status,
  closed,
}: {
  deadline?: string
  status?: string
  closed?: boolean
}) {
  const { t } = useTranslation()
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
      <span className="tabular-nums">{formatDate(deadline)}</span>
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
    </span>
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
  const { t } = useTranslation()
  const [more, setMore] = useState(false)
  const moreId = useId()
  const isHuman = HUMAN_SOURCES.has(finding.source)
  const locked = readOnly || isHuman
  // Re-scoring needs findings:severity, which a remediation owner may lack.
  const canRescore = useCanMutate('PATCH /api/v1/findings/{id}/severity')
  const asset = finding.assets[0]
  const crit = asset?.criticality
  const assetCaption = asset
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
      ]
        .filter(Boolean)
        .join(' · ')
    : ''
  const closed = CLOSED.has(triage.status)
  // People's labels only; scanner artefacts (tool, file, type) are noise here.
  const tags = userTags(finding)
  // A version-based match has no scanning tool behind it (RFC-066).
  const tool =
    finding.toolName === VERSION_MATCH_TOOL
      ? t('findings.properties.versionMatch', 'Version match')
      : [finding.toolName, finding.toolVersion].filter(Boolean).join(' ')

  return (
    <dl
      className={cn('space-y-1', className)}
      aria-label={t('findings.properties.ariaLabel', 'Properties')}
    >
      {!hideTriage && (
        <>
          <Row label={t('findings.properties.status', 'Status')}>
            <StatusSelect
              value={triage.status}
              onChange={triage.changeStatus}
              loading={triage.statusBusy}
              disabled={locked}
              source={finding.source}
            />
          </Row>
          <Row label={t('findings.properties.severity', 'Severity')}>
            <SeveritySelect
              value={triage.severity}
              onChange={triage.changeSeverity}
              loading={triage.severityBusy}
              disabled={locked || !canRescore}
              cvss={finding.cvss}
              showIcon={false}
            />
          </Row>
        </>
      )}
      {!hideTriage && (
        <Row label={t('findings.properties.priority', 'Priority')}>
          {finding.priorityClass ? (
            <span className="inline-flex items-center gap-1.5">
              <PriorityClassBadge priorityClass={finding.priorityClass} />
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
        </Row>
      )}
      {!hideTriage && (
        <Row label={t('findings.properties.assignee', 'Assignee')}>
          <AssigneeSelect
            disabled={locked}
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
        </Row>
      )}
      <Row label={t('findings.properties.slaDue', 'SLA due')}>
        <SlaDue deadline={finding.slaDeadline} status={finding.slaStatus} closed={closed} />
      </Row>

      {/* Below lg the rail sits above "Why it matters": keep the state rows
          visible and fold the rest. */}
      <div className="lg:hidden">
        <button
          type="button"
          className="mt-1 inline-flex items-center gap-1 rounded-sm text-xs text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-expanded={more}
          aria-controls={moreId}
          onClick={() => setMore((v) => !v)}
        >
          <ChevronRight
            className={cn('h-3 w-3 transition-transform', more && 'rotate-90')}
            aria-hidden
          />
          {more
            ? t('findings.properties.fewerDetails', 'Fewer details')
            : t('findings.properties.moreDetails', 'Asset, dates and more')}
        </button>
      </div>
      <div id={moreId} className={cn('space-y-1', !more && 'hidden lg:block')}>
        <div className="my-2 border-t" role="presentation" />

        {asset && (
          <Row label={t('findings.properties.asset', 'Asset')}>
            <span className="block min-w-0">
              {isLinkableAssetId(asset.id) ? (
                <Link
                  href={assetDetailHref(asset.id)}
                  className="rounded-sm font-medium break-words hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                >
                  {asset.name}
                  <ArrowUpRight className="ms-0.5 inline h-3.5 w-3.5 align-text-top" aria-hidden />
                </Link>
              ) : (
                <span className="font-medium">{asset.name}</span>
              )}
              {assetCaption && (
                <span className="block text-xs text-muted-foreground">{assetCaption}</span>
              )}
              {finding.assets.length > 1 && (
                <span className="block text-xs text-muted-foreground">
                  {t('findings.properties.moreAssets', '+{count} more', {
                    count: finding.assets.length - 1,
                  })}
                </span>
              )}
            </span>
          </Row>
        )}
        <Row label={t('findings.properties.foundBy', 'Found by')}>
          <span>
            {findingSourceLabel(finding.source)}
            {tool && <span className="block text-xs text-muted-foreground">{tool}</span>}
          </span>
        </Row>
        <Row label={t('findings.properties.firstSeen', 'First seen')}>
          <span title={finding.discoveredAt}>
            <span className="tabular-nums">{formatDate(finding.discoveredAt)}</span>
            <span className="block text-xs text-muted-foreground">
              <RelativeTime date={finding.discoveredAt} />
            </span>
          </span>
        </Row>
        {finding.lastSeenAt &&
          finding.lastSeenAt.slice(0, 10) !== finding.discoveredAt.slice(0, 10) && (
            <Row label={t('findings.properties.lastSeen', 'Last seen')}>
              <span className="tabular-nums" title={finding.lastSeenAt}>
                {formatDate(finding.lastSeenAt)}
              </span>
            </Row>
          )}
        {(finding.occurrenceCount ?? 0) > 1 && (
          <Row label={t('findings.properties.seenIn', 'Seen in')}>
            <span className="tabular-nums">
              {t('findings.properties.scansCount', '{count} scans', {
                count: finding.occurrenceCount ?? 0,
              })}
            </span>
          </Row>
        )}
        {finding.resolvedAt && (
          <Row label={t('findings.properties.resolved', 'Resolved')}>
            <span className="tabular-nums">{formatDate(finding.resolvedAt)}</span>
          </Row>
        )}
        {finding.closureReason && (
          <Row label={t('findings.properties.closedAs', 'Closed as')}>
            <span>
              {closureReasonLabel(t, finding.closureReason)}
              {finding.verification && (
                <span className="text-muted-foreground">
                  {' · '}
                  {verificationLabel(t, finding.verification)}
                </span>
              )}
            </span>
          </Row>
        )}
        {finding.workItemUris && finding.workItemUris.length > 0 && (
          <Row label={t('findings.properties.tickets', 'Tickets')}>
            <span className="flex flex-col gap-0.5">
              {finding.workItemUris.map((uri) => (
                <a
                  key={uri}
                  href={sanitizeExternalUrl(uri)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex min-w-0 items-center gap-1 text-sm hover:underline"
                >
                  <span className="truncate">{uri.replace(/^https?:\/\//, '')}</span>
                  <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                </a>
              ))}
            </span>
          </Row>
        )}
        {tags.length > 0 && (
          <Row label={t('findings.properties.tags', 'Tags')}>
            <span className="flex flex-wrap gap-1 py-1">
              {tags.map((tag) => (
                <Badge key={tag} variant="secondary" className="text-xs font-normal">
                  {tag}
                </Badge>
              ))}
            </span>
          </Row>
        )}
        {!hideTriage && (
          <Row label={t('findings.properties.id', 'ID')}>
            <DetailCopyId
              id={finding.id}
              label={t('findings.properties.findingId', 'Finding ID')}
            />
          </Row>
        )}
      </div>
    </dl>
  )
}
