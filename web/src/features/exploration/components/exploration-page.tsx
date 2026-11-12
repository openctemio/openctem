'use client'

/**
 * Exploration (api docs/architecture/exploration.md): the next steps the
 * platform plans to learn more about the attack surface. One status sentence
 * from the precomputed figures, then one list grouped as Waiting for you,
 * Next, Running and Done recently. Each row says what will be checked, on
 * which asset, why, how intrusive it is and how it ranks. `?asset=` narrows
 * the list to one asset (the asset page's "See all"); `?lead=` opens a step.
 */

import { useCallback, useMemo, useState } from 'react'
import { Check, Compass, X } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { RefreshButton } from '@/features/dashboards/components/dashboard-freshness'
import {
  BulkActionBar,
  EmptyState,
  ErrorState,
  Meter,
  MetaLine,
  PageHeader,
  FilterSelect,
  PageStack,
  TonePill,
} from '@/features/shared'
import { useAssetNameMap } from '@/features/threat-model/hooks/use-threat-model-refs'
import { useUrlFilter } from '@/hooks/use-url-param'
import { formatAbsoluteTime, formatRelativeTime } from '@/lib/format-metric'
import { Permission, usePermissions } from '@/lib/permissions'
import { useLeadSummary, useLeads } from '../hooks/use-leads'
import {
  approvableIds,
  canDismissLead,
  isLeadGroup,
  leadQuestion,
  reasonLabel,
  scoreShare,
  stateLabel,
  stateTone,
  statusSentence,
  tierKey,
  tierLabel,
  type Lead,
  type LeadGroup,
} from '../lib/leads'
import { LeadDetailSheet } from './lead-detail-sheet'
import { useLeadActions } from './lead-actions'

function StatusLine() {
  const { t, locale } = useTranslation()
  const { summary, error, isLoading, refresh } = useLeadSummary()
  if (isLoading) return <Skeleton className="h-5 w-2/3" />
  if (error || !summary) return null
  const rel = (iso: string) => formatRelativeTime(iso, locale)
  const org = summary.scope === 'organization'
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0 space-y-1">
        <p className="text-body" data-testid="exploration-status">
          {statusSentence(t, summary, rel)}
        </p>
        <MetaLine
          items={[
            org
              ? t('exploration.scope.organization', 'Organization-wide')
              : t('exploration.scope.mine', 'Your scope'),
            org && summary.computed_at && (
              <span key="updated" title={formatAbsoluteTime(summary.computed_at, locale)}>
                {t('exploration.freshness.updated', 'Updated {time}', {
                  time: formatRelativeTime(summary.computed_at, locale, new Date(), 'narrow'),
                })}
              </span>
            ),
            summary.done_30d > 0 &&
              t(
                'exploration.summary.done30d',
                '{done} answered in 30 days, {proven} confirmed, {refuted} nothing found',
                {
                  done: summary.done_30d,
                  proven: summary.proven_30d,
                  refuted: summary.refuted_30d,
                }
              ),
          ]}
        />
      </div>
      {org && <RefreshButton onRefresh={refresh} />}
    </div>
  )
}

function TierBadge({ tier }: { tier: number }) {
  const { t } = useTranslation()
  const key = tierKey(tier)
  return (
    <span
      className="inline-flex items-center rounded-sm border px-1.5 text-meta text-muted-foreground"
      data-tier={key}
    >
      {tierLabel(t, tier)}
    </span>
  )
}

function LeadRow({
  lead,
  maxScore,
  subject,
  selectable,
  selected,
  onSelect,
  onOpen,
}: {
  lead: Lead
  maxScore: number
  subject: string
  selectable: boolean
  selected: boolean
  onSelect: (checked: boolean) => void
  onOpen: () => void
}) {
  const { t } = useTranslation()
  const question = leadQuestion(t, lead.type)
  return (
    <li className="flex min-w-0 items-start gap-3 px-3 py-3" data-testid="exploration-lead">
      {selectable && (
        <Checkbox
          className="mt-1"
          checked={selected}
          onCheckedChange={(v) => onSelect(v === true)}
          aria-label={t('exploration.list.select', 'Select {question}', { question })}
        />
      )}
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex min-w-0 flex-wrap items-start justify-between gap-x-3 gap-y-1">
          <button
            type="button"
            onClick={onOpen}
            className="min-w-0 basis-48 flex-1 break-words text-start text-body font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {question}
          </button>
          <div className="flex shrink-0 items-center gap-3">
            {/* A div, not inside the meta line: the meter is a block element. */}
            <Meter
              value={Math.round(scoreShare(lead.score, maxScore) * 100)}
              max={100}
              label={t('exploration.list.score', 'Rank {score}', {
                score: lead.score.toFixed(2),
              })}
              className="w-12"
            />
            <TonePill tone={stateTone(lead.state)} label={stateLabel(t, lead.state)} />
          </div>
        </div>
        <MetaLine
          items={[
            lead.subject_asset_id ? (
              <Link
                key="subject"
                href={`/assets/${encodeURIComponent(lead.subject_asset_id)}`}
                className="text-foreground hover:underline"
              >
                {subject}
              </Link>
            ) : null,
            reasonLabel(t, lead.reason_code),
            <TierBadge key="tier" tier={lead.tier} />,
          ]}
        />
      </div>
    </li>
  )
}

function emptyText(t: ReturnType<typeof useTranslation>['t'], group: LeadGroup): string {
  switch (group) {
    case 'waiting':
      return t('exploration.empty.waiting', 'Nothing is waiting for you.')
    case 'next':
      return t('exploration.empty.next', 'No next steps planned.')
    case 'running':
      return t('exploration.empty.running', 'Nothing is running.')
    default:
      return t('exploration.empty.done', 'No step has finished yet.')
  }
}

export function ExplorationPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canApprove = can(Permission.ScansApprove)
  const [rawGroup, setGroup] = useUrlFilter('group', 'waiting')
  const group: LeadGroup = isLeadGroup(rawGroup) ? rawGroup : 'waiting'
  const [assetId, setAssetId] = useUrlFilter('asset', '')
  const [openLead, setOpenLead] = useUrlFilter('lead', '')
  const { leads, error, isLoading, hasMore, loadMore, loadingMore, mutate } = useLeads(
    group,
    assetId || undefined
  )
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const clear = useCallback(() => setSelected(new Set()), [])
  const actions = useLeadActions(clear)

  const subjectIds = useMemo(
    () => [...leads.map((l) => l.subject_asset_id ?? ''), assetId].filter(Boolean),
    [leads, assetId]
  )
  const { nameFor } = useAssetNameMap(subjectIds)
  const maxScore = useMemo(() => Math.max(0, ...leads.map((l) => l.score)), [leads])
  const selectable = group === 'waiting' && canApprove

  const changeGroup = (g: LeadGroup) => {
    clear()
    setGroup(g)
  }
  const toggle = (id: string, on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (on) next.add(id)
      else next.delete(id)
      return next
    })

  const approveIds = approvableIds(leads, selected)
  const dismissIds = leads.filter((l) => selected.has(l.id) && canDismissLead(l)).map((l) => l.id)

  return (
    <PageStack>
      <PageHeader
        title={t('exploration.title', 'Exploration')}
        description={t(
          'exploration.description',
          'The next steps the platform plans to learn more about your attack surface, and what they found.'
        )}
      />
      <StatusLine />
      <div className="flex flex-wrap items-center gap-3">
        <FilterSelect<LeadGroup>
          label={t('exploration.groups.label', 'Steps')}
          value={group}
          clearable={false}
          onChange={(v) => v && changeGroup(v)}
          options={[
            { value: 'waiting', label: t('exploration.groups.waiting', 'Waiting for you') },
            { value: 'next', label: t('exploration.groups.next', 'Next') },
            { value: 'running', label: t('exploration.groups.running', 'Running') },
            { value: 'done', label: t('exploration.groups.done', 'Done recently') },
          ]}
        />
        {assetId && (
          <span className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-sm">
            {t('exploration.assetFilter', 'Asset: {name}', { name: nameFor(assetId) })}
            <button
              type="button"
              className="rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => setAssetId('')}
              aria-label={t('exploration.assetFilterClear', 'Show every asset')}
            >
              <X className="h-3.5 w-3.5" aria-hidden />
            </button>
          </span>
        )}
      </div>

      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      ) : error ? (
        <ErrorState
          title={t('exploration.list.errorTitle', 'next steps')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : leads.length === 0 ? (
        <EmptyState icon={Compass} title={emptyText(t, group)} />
      ) : (
        <div className="space-y-3">
          <ul
            className="divide-y rounded-lg border bg-card"
            aria-label={t('exploration.list.label', 'Next steps')}
          >
            {leads.map((l) => (
              <LeadRow
                key={l.id}
                lead={l}
                maxScore={maxScore}
                subject={nameFor(l.subject_asset_id)}
                selectable={selectable}
                selected={selected.has(l.id)}
                onSelect={(on) => toggle(l.id, on)}
                onOpen={() => setOpenLead(l.id)}
              />
            ))}
          </ul>
          {hasMore && (
            <div className="flex justify-center">
              <Button variant="outline" size="sm" onClick={loadMore} disabled={loadingMore}>
                {t('exploration.list.loadMore', 'Load more')}
              </Button>
            </div>
          )}
        </div>
      )}

      <BulkActionBar
        count={selected.size}
        onClear={clear}
        noun={t('exploration.list.selected', 'selected')}
      >
        <Button
          size="sm"
          disabled={actions.busy || approveIds.length === 0}
          onClick={() => void actions.approve(approveIds)}
        >
          <Check className="me-1.5 h-4 w-4" aria-hidden />
          {t('exploration.actions.approveCount', 'Approve {count}', { count: approveIds.length })}
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={actions.busy || dismissIds.length === 0}
          onClick={() => actions.askDismiss(dismissIds)}
        >
          <X className="me-1.5 h-4 w-4" aria-hidden />
          {t('exploration.actions.dismissCount', 'Dismiss {count}', { count: dismissIds.length })}
        </Button>
      </BulkActionBar>

      <LeadDetailSheet
        leadId={openLead || null}
        onOpenChange={(open) => !open && setOpenLead('')}
        onOpenLead={setOpenLead}
        onApprove={(ids) => void actions.approve(ids)}
        onDismiss={actions.askDismiss}
        subjectName={nameFor}
      />
      {actions.dialog}
    </PageStack>
  )
}
