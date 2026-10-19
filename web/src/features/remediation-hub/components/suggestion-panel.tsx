'use client'

/**
 * The detail of one suggestion, in a side panel (?suggestion=<id>): what the
 * fix is, which findings it closes and where, the assets and their owners,
 * why the findings were grouped and how sure the grouping is, and exactly
 * what accepting creates. Findings can be left out and owners changed before
 * accepting. Scanner text is shown as plain text only.
 */

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ChevronLeft, ChevronRight, Clock, Sparkles, XCircle } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailHeader, DetailSheet } from '@/features/shared/components/detail-sheet-layout'
import {
  DetailCallout,
  DetailDisclosure,
  DetailSection,
  DetailSections,
} from '@/features/shared/components/detail-sheet'
import { TruncatedText } from '@/features/shared/components/truncated-text'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { CriticalityBadge } from '@/features/assets/components/classification-badges'
import type { Severity } from '@/features/shared'
import type { PriorityClass } from '@/features/findings/types/finding.types'
import type { Criticality } from '@/features/assets/types/asset.types'
import type { RemediationSuggestion, SuggestionMember } from '../api/types'
import type { ApproveBody } from '../api/use-remediation-hub'
import { useSuggestionMembers } from '../api/use-remediation-hub'
import { useOwnerNames } from '../api/use-owner-names'
import { fixSteps } from '../lib/hub'
import {
  acceptPreview,
  basisFactors,
  basisRules,
  confidenceBand,
  crossesMajor,
  installedVersions,
  memberAssets,
  memberLocation,
} from '../lib/suggestion-detail'
import { FixStepsBlock } from './fix-steps'
import { OwnerCombobox, type OwnerValue } from './owner-combobox'
import { RiskPoints } from './risk-points'

const PER_PAGE = 50

export interface SuggestionPanelProps {
  suggestion: RemediationSuggestion | null
  /** Still loading a suggestion named by the URL. */
  loading?: boolean
  open: boolean
  onOpenChange: (open: boolean) => void
  canWrite: boolean
  canOwnerAccept: boolean
  busy?: boolean
  onAccept: (body: Omit<ApproveBody, 'version'>) => void
  onEdit: () => void
  onDismiss: () => void
  onSnooze: () => void
  /** Position in the inbox, for "3 of 25" and the previous/next buttons. */
  position?: { index: number; total: number }
  onPrev?: () => void
  onNext?: () => void
}

function dateLabel(iso: string | undefined, locale: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? ''
    : d.toLocaleDateString(locale, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function SuggestionPanel({
  suggestion: s,
  loading,
  open,
  onOpenChange,
  canWrite,
  canOwnerAccept,
  busy,
  onAccept,
  onEdit,
  onDismiss,
  onSnooze,
  position,
  onPrev,
  onNext,
}: SuggestionPanelProps) {
  const { t, locale } = useTranslation()
  const owners = useOwnerNames()
  const [page, setPage] = useState(1)
  const [excluded, setExcluded] = useState<Set<string>>(new Set())
  const [overrides, setOverrides] = useState<Record<number, OwnerValue>>({})
  const { data: members, isLoading: membersLoading } = useSuggestionMembers(
    open ? s?.id : undefined,
    page,
    PER_PAGE
  )
  useEffect(() => {
    setPage(1)
    setExcluded(new Set())
    setOverrides({})
  }, [s?.id])

  const rows = useMemo(() => members?.data ?? [], [members])
  const blocked = (s?.hidden_members ?? 0) > 0
  const canAct = (canWrite || canOwnerAccept) && !blocked
  const preview = s ? acceptPreview(s, excluded) : null
  const pages = members ? Math.max(1, Math.ceil(members.total / members.per_page)) : 1

  const body = useMemo((): Omit<ApproveBody, 'version'> => {
    const out: Omit<ApproveBody, 'version'> = {}
    if (excluded.size) out.exclude_finding_ids = [...excluded]
    const os = Object.entries(overrides).map(([k, v]) => ({
      index: Number(k),
      ...(v.userId ? { assignee_user_id: v.userId } : {}),
      ...(v.groupId ? { assignee_group_id: v.groupId } : {}),
    }))
    if (os.length) out.owners = os
    return out
  }, [excluded, overrides])

  const ownerName = (v: OwnerValue) =>
    [owners.user(v.userId), owners.group(v.groupId)].filter(Boolean).join(' · ') ||
    (v.userId || v.groupId
      ? t('remediationHub.ownerPicker.unknown')
      : t('remediationHub.owner.defaultQueue'))

  const header = (
    <DetailHeader
      title={s?.title ?? t('remediationHub.panel.loading')}
      badges={
        s && (
          <>
            <Badge variant="outline">{t(`remediationHub.kind.${s.kind}`)}</Badge>
            {s.has_urgent && (
              <Badge variant="destructive" className="gap-1">
                <AlertTriangle className="size-3" aria-hidden />
                {t('remediationHub.suggestions.urgent')}
              </Badge>
            )}
          </>
        )
      }
      meta={
        s
          ? [
              t('remediationHub.suggestions.findingsCount', undefined, { n: s.member_count }),
              t('remediationHub.suggestions.assetsCount', undefined, {
                n: s.risk_parts?.assets ?? 0,
              }),
              <RiskPoints key="risk" suggestion={s} />,
              position
                ? t('remediationHub.panel.position', undefined, {
                    n: position.index + 1,
                    total: position.total,
                  })
                : null,
            ].filter(Boolean)
          : []
      }
      actions={
        s && (
          <div className="flex flex-wrap items-center gap-2">
            {canAct && (
              <Button
                size="sm"
                onClick={() => onAccept(canWrite ? body : {})}
                disabled={busy || (preview?.kept ?? 0) <= 0}
              >
                {canWrite
                  ? t('remediationHub.accept.confirm', undefined, { n: preview?.kept ?? 0 })
                  : t('remediationHub.ownerAccept.action')}
              </Button>
            )}
            {canWrite && !blocked && (
              <Button size="sm" variant="outline" onClick={onEdit} disabled={busy}>
                {t('remediationHub.actions.edit')}
              </Button>
            )}
            {onPrev && (
              <Button
                size="icon"
                variant="ghost"
                className="size-8"
                onClick={onPrev}
                disabled={!position || position.index <= 0}
                aria-label={t('remediationHub.panel.previous')}
                aria-keyshortcuts="k"
              >
                <ChevronLeft className="size-4" aria-hidden />
              </Button>
            )}
            {onNext && (
              <Button
                size="icon"
                variant="ghost"
                className="size-8"
                onClick={onNext}
                disabled={!position || position.index >= position.total - 1}
                aria-label={t('remediationHub.panel.next')}
                aria-keyshortcuts="j"
              >
                <ChevronRight className="size-4" aria-hidden />
              </Button>
            )}
          </div>
        )
      }
      menu={
        s && canWrite && !blocked
          ? [
              { label: t('remediationHub.actions.snoozeUntil'), icon: Clock, onSelect: onSnooze },
              { label: t('remediationHub.actions.dismiss'), icon: XCircle, onSelect: onDismiss },
            ]
          : undefined
      }
      onClose={() => onOpenChange(false)}
    />
  )

  return (
    <DetailSheet open={open} onOpenChange={onOpenChange} header={header} width="xl">
      {!s ? (
        <div className="space-y-3 p-1" aria-busy={loading ? 'true' : undefined}>
          {loading ? (
            <>
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-48 w-full" />
            </>
          ) : (
            <p className="text-muted-foreground text-sm">{t('remediationHub.panel.notFound')}</p>
          )}
        </div>
      ) : (
        <DetailSections>
          {blocked && (
            <DetailCallout tone="warning" title={t('remediationHub.panel.blockedTitle')}>
              {t('remediationHub.suggestions.hidden', undefined, { n: s.hidden_members })}
            </DetailCallout>
          )}

          <AcceptPreviewSection
            s={s}
            preview={preview}
            canEdit={canWrite && !blocked}
            overrides={overrides}
            setOverrides={setOverrides}
            ownerName={ownerName}
            owners={owners}
            locale={locale}
          />

          <FixSection s={s} members={rows} />

          <DetailSection
            title={t('remediationHub.panel.findings')}
            count={members?.total ?? s.member_count - s.hidden_members}
          >
            {membersLoading && !members ? (
              <Skeleton className="h-32 w-full" />
            ) : (
              <FindingsTable
                rows={rows}
                excluded={excluded}
                canExclude={canWrite && !blocked}
                onToggle={(id, keep) =>
                  setExcluded((cur) => {
                    const n = new Set(cur)
                    if (keep) n.delete(id)
                    else n.add(id)
                    return n
                  })
                }
                locale={locale}
              />
            )}
            {pages > 1 && (
              <div className="mt-2 flex items-center justify-end gap-2 text-xs">
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  {t('remediationHub.actions.previous')}
                </Button>
                <span>{t('remediationHub.pageOf', undefined, { page, pages })}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={page >= pages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  {t('remediationHub.actions.next')}
                </Button>
              </div>
            )}
          </DetailSection>

          <AssetsSection members={rows} s={s} ownerName={ownerName} />

          <WhySection s={s} />
        </DetailSections>
      )}
    </DetailSheet>
  )
}

function AcceptPreviewSection({
  s,
  preview,
  canEdit,
  overrides,
  setOverrides,
  ownerName,
  owners,
  locale,
}: {
  s: RemediationSuggestion
  preview: ReturnType<typeof acceptPreview> | null
  canEdit: boolean
  overrides: Record<number, OwnerValue>
  setOverrides: React.Dispatch<React.SetStateAction<Record<number, OwnerValue>>>
  ownerName: (v: OwnerValue) => string
  owners: ReturnType<typeof useOwnerNames>
  locale: string
}) {
  const { t } = useTranslation()
  if (!preview) return null
  const due = dateLabel(s.earliest_deadline, locale)
  return (
    <DetailSection title={t('remediationHub.panel.acceptCreates')} icon={Sparkles}>
      <div className="space-y-3 text-sm" data-testid="accept-preview">
        {preview.joins ? (
          <p>{t('remediationHub.panel.joinsTask', undefined, { n: preview.kept })}</p>
        ) : (
          <>
            <p>{t('remediationHub.panel.createsTasks', undefined, { n: preview.tasks.length })}</p>
            <ul className="space-y-2">
              {preview.tasks.map((p) => {
                const suggested = { userId: p.ownerUserId, groupId: p.ownerGroupId }
                const value = overrides[p.index] ?? suggested
                return (
                  <li
                    key={p.index}
                    className="grid gap-2 rounded-md border p-2 sm:grid-cols-[1fr_minmax(12rem,1.2fr)] sm:items-center"
                  >
                    <span>
                      {t('remediationHub.panel.taskN', undefined, { n: p.index + 1 })}
                      {' · '}
                      {t('remediationHub.suggestions.findingsCount', undefined, { n: p.findings })}
                    </span>
                    {canEdit ? (
                      <OwnerCombobox
                        label={t('remediationHub.panel.ownerOf', undefined, { n: p.index + 1 })}
                        value={value}
                        suggested={p.assetOwner ? suggested : undefined}
                        onChange={(v) => setOverrides((o) => ({ ...o, [p.index]: v }))}
                        users={owners.users}
                        groups={owners.groups}
                        usersState={owners.usersState}
                        groupsState={owners.groupsState}
                      />
                    ) : (
                      <span className="text-muted-foreground">{ownerName(value)}</span>
                    )}
                  </li>
                )
              })}
            </ul>
          </>
        )}
        <p className="text-muted-foreground text-xs">
          {due
            ? t('remediationHub.panel.deadline', undefined, { date: due })
            : t('remediationHub.panel.noDeadline')}
        </p>
      </div>
    </DetailSection>
  )
}

function FixSection({ s, members }: { s: RemediationSuggestion; members: SuggestionMember[] }) {
  const { t } = useTranslation()
  const steps = fixSteps(s.fix_spec, s.action_key)
  const current = installedVersions(members)
  const breaking = steps.kind === 'upgrade' && current.some((v) => crossesMajor(v, steps.target))
  const solution = members.find((m) => m.recommendation)?.recommendation
  const code = members.find((m) => m.fix_code)?.fix_code
  const source = typeof s.fix_spec?.source === 'string' ? s.fix_spec.source : undefined
  return (
    <DetailSection title={t('remediationHub.panel.fix')}>
      <div className="space-y-3" data-testid="panel-fix">
        {steps.kind === 'upgrade' && current.length > 0 && (
          <p className="text-sm">
            {t('remediationHub.panel.upgradeFrom', undefined, {
              pkg: steps.pkg ?? '',
              current: current.slice(0, 5).join(', '),
              target: steps.target ?? '',
            })}
          </p>
        )}
        {breaking && (
          <DetailCallout tone="warning" title={t('remediationHub.panel.majorTitle')}>
            {t('remediationHub.panel.majorHint')}
          </DetailCallout>
        )}
        {steps.kind === 'sol' && solution ? (
          <p className="text-sm break-words whitespace-pre-wrap" data-testid="panel-solution">
            {solution}
          </p>
        ) : (
          <FixStepsBlock steps={steps} />
        )}
        {code && (
          <div className="space-y-1">
            <p className="text-muted-foreground text-xs">{t('remediationHub.panel.fixCode')}</p>
            <pre className="bg-muted/50 max-h-64 overflow-auto rounded-md border p-2 font-mono text-xs whitespace-pre">
              {code}
            </pre>
          </div>
        )}
        {source && (
          <p className="text-muted-foreground text-xs">
            {t('remediationHub.panel.source', undefined, { source })}
          </p>
        )}
      </div>
    </DetailSection>
  )
}

function FindingsTable({
  rows,
  excluded,
  canExclude,
  onToggle,
  locale,
}: {
  rows: SuggestionMember[]
  excluded: ReadonlySet<string>
  canExclude: boolean
  onToggle: (id: string, keep: boolean) => void
  locale: string
}) {
  const { t } = useTranslation()
  if (rows.length === 0)
    return <p className="text-muted-foreground text-sm">{t('remediationHub.panel.noFindings')}</p>
  return (
    <ul className="divide-y rounded-md border" data-testid="panel-findings">
      {rows.map((m) => {
        const kept = !excluded.has(m.finding_id)
        const loc = memberLocation(m)
        const due = dateLabel(m.sla_deadline, locale)
        return (
          <li key={m.finding_id} className="flex items-start gap-3 px-3 py-2">
            {canExclude && (
              <Checkbox
                className="mt-0.5"
                checked={kept}
                onCheckedChange={(v) => onToggle(m.finding_id, v === true)}
                aria-label={t('remediationHub.accept.keep', undefined, { title: m.title })}
              />
            )}
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={m.severity as Severity} />
                {m.priority_class && (
                  <PriorityClassBadge
                    priorityClass={m.priority_class as PriorityClass}
                    assetId={m.asset_id}
                  />
                )}
                <span className={kept ? 'text-sm' : 'text-muted-foreground text-sm line-through'}>
                  {m.title}
                </span>
              </div>
              <div className="text-muted-foreground flex flex-wrap gap-x-3 gap-y-1 text-xs">
                <TruncatedText
                  value={loc.full}
                  middle={60}
                  className="max-w-full font-mono"
                  label={t('remediationHub.panel.location')}
                />
                {m.rule_id && (
                  <span>{t('remediationHub.panel.rule', undefined, { rule: m.rule_id })}</span>
                )}
                {m.cwe_ids && m.cwe_ids.length > 0 && (
                  <span>{m.cwe_ids.slice(0, 3).join(', ')}</span>
                )}
                <span>{t(`remediationHub.findingStatus.${m.status}`, m.status)}</span>
                {due && <span>{t('remediationHub.panel.due', undefined, { date: due })}</span>}
              </div>
              {m.active_task && (
                <p className="text-warning text-xs">
                  {t('remediationHub.panel.claimed', undefined, { title: m.active_task.title })}
                </p>
              )}
            </div>
          </li>
        )
      })}
    </ul>
  )
}

function AssetsSection({
  members,
  s,
  ownerName,
}: {
  members: SuggestionMember[]
  s: RemediationSuggestion
  ownerName: (v: OwnerValue) => string
}) {
  const { t } = useTranslation()
  const assets = memberAssets(members)
  const ownerOf = (findingId: string) => {
    const p = s.partitions.find((x) => x.finding_ids.includes(findingId))
    if (!p) return ''
    if (p.owner_rule === 'default_queue') return t('remediationHub.owner.defaultQueue')
    return ownerName({ userId: p.owner_user_id, groupId: p.owner_group_id })
  }
  if (assets.length === 0) return null
  return (
    <DetailSection title={t('remediationHub.panel.assets')} count={assets.length}>
      <ul className="divide-y rounded-md border text-sm">
        {assets.map((a) => {
          const first = members.find((m) => m.asset_id === a.id)
          return (
            <li key={a.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
              <TruncatedText value={a.name} className="min-w-0 flex-1 font-medium" />
              {a.criticality && (
                <CriticalityBadge criticality={a.criticality as Criticality} size="sm" />
              )}
              <span className="text-muted-foreground text-xs">
                {t('remediationHub.panel.primaryOwner', undefined, {
                  owner: first ? ownerOf(first.finding_id) : '',
                })}
              </span>
            </li>
          )
        })}
      </ul>
    </DetailSection>
  )
}

function WhySection({ s }: { s: RemediationSuggestion }) {
  const { t } = useTranslation()
  const factors = basisFactors(s)
  const rules = basisRules(s)
  const band = confidenceBand(s.confidence)
  const pct = Math.round(s.confidence * 100)
  return (
    <DetailSection title={t('remediationHub.panel.why')}>
      <div className="space-y-2 text-sm" data-testid="panel-why">
        <ul className="list-disc space-y-1 ps-5">
          {factors.map((f) => (
            <li key={f}>{t(`remediationHub.basis.${f}`)}</li>
          ))}
        </ul>
        {rules.length > 0 && (
          <p className="text-muted-foreground text-xs break-words">
            {t('remediationHub.panel.rules', undefined, { rules: rules.join(', ') })}
          </p>
        )}
        <p>{t(`remediationHub.confidence.${band}`, undefined, { pct })}</p>
        {s.kind !== 'new_group' && (
          <p className="text-muted-foreground text-xs">
            {t(`remediationHub.explain.kind.${s.kind}`)}
          </p>
        )}
        <DetailDisclosure summary={t('remediationHub.panel.technical')}>
          <p className="text-muted-foreground text-xs break-all">
            {t('remediationHub.explain.key', undefined, { key: s.action_key })}
          </p>
          <p className="text-muted-foreground text-xs">
            {t('remediationHub.explain.algorithm', undefined, {
              algorithm: s.algorithm,
              version: s.algorithm_version,
            })}
          </p>
        </DetailDisclosure>
      </div>
    </DetailSection>
  )
}
