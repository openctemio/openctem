'use client'

/**
 * The finding's properties (who, when and where) as a
 * label → value list in the page's right rail (and in the drawer). Status,
 * severity and assignee are editable in place through `useFindingTriage`.
 *
 * Read top to bottom: state (status, severity, priority, assignee, SLA), then
 * where (asset, source), then when (first / last seen), then trivia.
 */

import { findingStatusesInCategory } from '@/features/findings/types/finding.types'
import Link from '@/components/link'
import { useId, useState } from 'react'
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
import { AssigneeSelect } from '../assignee-select'
import { PriorityClassBadge } from '../priority-class-badge'
import { findingAssetTypeLabel } from '../../lib/finding-asset-type'
import { assetDetailHref, isLinkableAssetId } from '../../lib/asset-link'
import { findingSourceLabel, HUMAN_SOURCES } from '../../lib/finding-detail'
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
  if (!deadline) return <span className="text-muted-foreground">No SLA</span>
  const days = daysUntil(deadline)
  const late = days !== null && days < 0
  const rel =
    days === null
      ? ''
      : days === 0
        ? 'due today'
        : late
          ? `${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'} overdue`
          : `${days} day${days === 1 ? '' : 's'} left`
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
   * Leave out status, severity and assignee: the drawer edits those in its
   * header row and lists only the rest here.
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
  const [more, setMore] = useState(false)
  const moreId = useId()
  const isHuman = HUMAN_SOURCES.has(finding.source)
  const locked = readOnly || isHuman
  const asset = finding.assets[0]
  const crit = asset?.criticality
  const assetCaption = asset
    ? [
        findingAssetTypeLabel(asset.type),
        crit === 'critical'
          ? 'Critical asset'
          : crit === 'none'
            ? 'Criticality not rated'
            : crit
              ? `${CRITICALITY_LABELS[crit]} criticality`
              : null,
        asset.exposure && asset.exposure !== 'unknown'
          ? asset.exposure.charAt(0).toUpperCase() + asset.exposure.slice(1)
          : null,
      ]
        .filter(Boolean)
        .join(' · ')
    : ''
  const closed = CLOSED.has(triage.status)
  const tool = [finding.toolName, finding.toolVersion].filter(Boolean).join(' ')

  return (
    <dl className={cn('space-y-1', className)} aria-label="Properties">
      {!hideTriage && (
        <>
          <Row label="Status">
            <StatusSelect
              value={triage.status}
              onChange={triage.changeStatus}
              loading={triage.statusBusy}
              disabled={locked}
              source={finding.source}
            />
          </Row>
          <Row label="Severity">
            <SeveritySelect
              value={triage.severity}
              onChange={triage.changeSeverity}
              loading={triage.severityBusy}
              disabled={locked}
              cvss={finding.cvss}
              showIcon={false}
            />
          </Row>
        </>
      )}
      <Row label="Priority">
        {finding.priorityClass ? (
          <span className="inline-flex items-center gap-1.5">
            <PriorityClassBadge priorityClass={finding.priorityClass} />
            {finding.priorityClassOverride && (
              <span className="text-xs text-muted-foreground">set manually</span>
            )}
          </span>
        ) : (
          <span className="text-muted-foreground">Not classified</span>
        )}
      </Row>
      {!hideTriage && (
        <Row label="Assignee">
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
            placeholder="Unassigned"
          />
        </Row>
      )}
      <Row label="SLA due">
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
          {more ? 'Fewer details' : 'Asset, dates and more'}
        </button>
      </div>
      <div id={moreId} className={cn('space-y-1', !more && 'hidden lg:block')}>
        <div className="my-2 border-t" role="presentation" />

        {asset && (
          <Row label="Asset">
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
                  +{finding.assets.length - 1} more
                </span>
              )}
            </span>
          </Row>
        )}
        <Row label="Found by">
          <span>
            {findingSourceLabel(finding.source)}
            {tool && <span className="block text-xs text-muted-foreground">{tool}</span>}
          </span>
        </Row>
        <Row label="First seen">
          <span title={finding.discoveredAt}>
            <span className="tabular-nums">{formatDate(finding.discoveredAt)}</span>
            <span className="block text-xs text-muted-foreground">
              <RelativeTime date={finding.discoveredAt} />
            </span>
          </span>
        </Row>
        {finding.lastSeenAt &&
          finding.lastSeenAt.slice(0, 10) !== finding.discoveredAt.slice(0, 10) && (
            <Row label="Last seen">
              <span className="tabular-nums" title={finding.lastSeenAt}>
                {formatDate(finding.lastSeenAt)}
              </span>
            </Row>
          )}
        {(finding.occurrenceCount ?? 0) > 1 && (
          <Row label="Occurrences">
            <span className="tabular-nums">{finding.occurrenceCount}</span>
          </Row>
        )}
        {finding.resolvedAt && (
          <Row label="Resolved">
            <span className="tabular-nums">{formatDate(finding.resolvedAt)}</span>
          </Row>
        )}
        {finding.workItemUris && finding.workItemUris.length > 0 && (
          <Row label="Tickets">
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
        {finding.tags && finding.tags.length > 0 && (
          <Row label="Tags">
            <span className="flex flex-wrap gap-1 py-1">
              {finding.tags.map((t) => (
                <Badge key={t} variant="secondary" className="text-xs font-normal">
                  {t}
                </Badge>
              ))}
            </span>
          </Row>
        )}
        <Row label="ID">
          <DetailCopyId id={finding.id} label="Finding ID" />
        </Row>
      </div>
    </dl>
  )
}
