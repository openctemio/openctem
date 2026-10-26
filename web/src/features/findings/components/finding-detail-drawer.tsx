'use client'

/**
 * The findings list's quick view. Same answers as the detail page, shorter:
 * what it is, why it matters, how to fix it, who owns it by when. It renders
 * the page's own sections (FindingWhyItMatters, FindingFixCard,
 * FindingProperties, useFindingTriage) so the drawer and the page cannot
 * disagree about a finding or about the approval rules.
 *
 * Opens immediately with the list row's data, then fills in from
 * GET /findings/{id} (package, advisory, asset criticality).
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import {
  ChevronLeft,
  ChevronRight,
  Copy,
  ExternalLink,
  FileText,
  Link2,
  ShieldCheck,
  Ticket,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { copyToClipboard } from '@/lib/clipboard'
import { DetailSection, DetailSections } from '@/features/shared/components/detail-sheet'
import {
  DetailHeader,
  DetailSheet,
  DetailSheetFooter,
  type DetailMenuItem,
} from '@/features/shared/components/detail-sheet-layout'
import type { Severity } from '@/features/shared/types'
import { useFindingApi, useFindingApprovals } from '../api/use-findings-api'
import { useFindingTriage } from '../hooks/use-finding-triage'
import { findingDescription, isTriageLocked, toFindingDetail } from '../lib/finding-detail'
import { displayTitle } from '../lib/finding-display'
import {
  APPROVAL_STATUS_CONFIG,
  FINDING_STATUS_CONFIG,
  type ApiApproval,
  type ApprovalStatus,
  type Finding,
  type FindingDetail,
  type FindingStatus,
  type FindingUser,
} from '../types'
import { AssigneeSelect } from './assignee-select'
import { CreateTicketDialog } from './create-ticket-dialog'
import { useCanCreateTicket } from '../hooks/use-can-create-ticket'
import { SeveritySelect } from './severity-select'
import { useCanMutate } from '@/lib/permissions'
import { StatusSelect } from './status-select'
import { FindingWhyItMatters } from './detail/finding-why-it-matters'
import { FindingApprovalBand } from './detail/finding-approval-band'
import { FindingFixCard } from './detail/finding-fix-card'
import { FindingTaskBand } from '@/features/remediation-hub/components/finding-task-band'
import { FindingAssetName } from './detail/finding-asset-name'
import { FindingProperties } from './detail/finding-properties'
import { FindingProvenanceSection } from './detail/finding-provenance-section'
import { FindingIssueGroupSection } from './detail/finding-issue-group-section'
import { FindingIdentitySection } from './detail/finding-identity-section'
import { FindingTypePanel } from './detail/finding-type-panel'
import {
  FindingCodeLocation,
  codeLocationOf,
  showDrawerCodeLocation,
} from './detail/finding-code-location'
import { FindingIntelSection } from './detail/finding-intel-section'
import { FindingRetestSection } from './detail/finding-retest'
import { VerificationPanel } from './detail/verification-panel'
import { FindingRetestCheckSection } from './detail/finding-retest-check'
import { FindingTenableRescanSection } from './detail/finding-tenable-rescan'
import { FindingActivity } from './finding-activity'
import { AdvisoryText } from './detail/advisory-text'
import type { EntityActivityHandle } from '@/features/activity/components/entity-activity'
import { AIProposalBadge } from './ai-proposal-badge'
import { toDisplayText } from '@/lib/untrusted-text'
import { formatAbsoluteTime, formatRelativeTime } from '@/lib/format-metric'

/** The drawer inside a task: position in the task's findings and the task to return to. */
export interface FindingDrawerTaskNav {
  taskId: string
  /** 1-based position and the number of findings. */
  index: number
  total: number
  onPrev?: () => void
  onNext?: () => void
}

interface FindingDetailDrawerProps {
  /** Set when the drawer is opened from a task's findings. */
  taskNav?: FindingDrawerTaskNav
  finding: Finding | null
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Show skeleton loading state */
  isLoading?: boolean
  onStatusChange?: (findingId: string, status: FindingStatus) => void
  onSeverityChange?: (findingId: string, severity: Severity) => void
  onAssigneeChange?: (findingId: string, assignee: FindingUser | null) => void
}

function DrawerBodySkeleton() {
  return (
    <div className="space-y-4" aria-busy>
      <Skeleton className="h-28 w-full rounded-lg" />
      <Skeleton className="h-20 w-full rounded-lg" />
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="grid grid-cols-[6.5rem_1fr] gap-3">
          <Skeleton className="h-3.5 w-16" />
          <Skeleton className="h-4 w-40" />
        </div>
      ))}
    </div>
  )
}

export function FindingDetailDrawer({
  finding,
  open,
  onOpenChange,
  isLoading = false,
  onStatusChange,
  onSeverityChange,
  onAssigneeChange,
  taskNav,
}: FindingDetailDrawerProps) {
  const { t, locale } = useTranslation()
  const router = useRouter()
  const canCreateTicket = useCanCreateTicket()
  const [ticketOpen, setTicketOpen] = useState(false)
  const activityRef = useRef<EntityActivityHandle>(null)

  // The full record: package, advisory, asset criticality. Only while open.
  const { data: api } = useFindingApi(open && finding ? finding.id : null)
  const detail: FindingDetail | null =
    api && finding && api.id === finding.id
      ? toFindingDetail(api)
      : finding
        ? { ...finding, activities: [] }
        : null

  // Re-scoring needs findings:severity, which a remediation owner may lack.
  const canRescore = useCanMutate('PATCH /api/v1/findings/{id}/severity')
  const canAssign = useCanMutate('POST /api/v1/findings/{id}/assign')
  const locked = isTriageLocked(detail?.source)
  const triage = useFindingTriage(
    detail ?? { id: '', status: 'new', severity: 'medium', assignee: undefined },
    {
      onStatusChange: (s) => finding && onStatusChange?.(finding.id, s),
      onSeverityChange: (s) => finding && onSeverityChange?.(finding.id, s),
      onAssigneeChange: (u) => finding && onAssigneeChange?.(finding.id, u),
    }
  )

  const { data: approvals } = useFindingApprovals(
    // Whatever the status: a pending request exists before the status moves.
    open && finding ? finding.id : undefined
  )

  // Pending requests are shown by the approval band, not repeated here.
  const decided = (approvals ?? []).filter((a) => a.status !== 'pending')

  const openPage = useCallback(
    (tab?: string) => {
      if (!finding) return
      onOpenChange(false)
      const q = new URLSearchParams()
      if (tab) q.set('tab', tab)
      if (taskNav) q.set('from', `task:${taskNav.taskId}`)
      const qs = q.toString()
      router.push(`/findings/${finding.id}${qs ? `?${qs}` : ''}`)
    },
    [finding, onOpenChange, router, taskNav]
  )

  // ⌘/Ctrl+Enter opens the full page. The platform copy chord is left alone:
  // the activity panel's own "C" key opens the comment box.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && el.tagName !== 'TEXTAREA') {
        e.preventDefault()
        openPage()
      }
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
  }, [open, openPage])

  if (!finding || !detail) return null

  const menu: DetailMenuItem[] = [
    {
      label: t('findings.drawer.copyLink', 'Copy link'),
      icon: Link2,
      onSelect: () => {
        void copyToClipboard(`${window.location.origin}/findings/${finding.id}`).then((ok) =>
          ok
            ? toast.success(t('findings.drawer.linkCopied', 'Link copied'))
            : toast.error(t('findings.toast.copyFailed', 'Could not copy to the clipboard'))
        )
      },
    },
    {
      label: t('findings.drawer.copyId', 'Copy finding ID'),
      icon: Copy,
      onSelect: () => {
        void copyToClipboard(finding.id).then((ok) =>
          ok
            ? toast.success(t('findings.drawer.idCopied', 'Finding ID copied'))
            : toast.error(t('findings.toast.copyFailed', 'Could not copy to the clipboard'))
        )
      },
    },
    ...(canCreateTicket
      ? [
          {
            label: t('findings.drawer.createTicket', 'Create ticket'),
            icon: Ticket,
            onSelect: () => setTicketOpen(true),
          },
        ]
      : []),
  ]

  const asset = detail.assets[0]
  // The row has no description yet (it may carry the code snippet): wait
  // for the full record rather than flash the wrong text.
  const description = api ? findingDescription(detail) : { text: '', fromAdvisory: false }
  const c = detail.component
  const where = c
    ? `${c.name} ${c.version}`
    : detail.filePath
      ? `${detail.filePath}${detail.startLine ? `:${detail.startLine}` : ''}`
      : undefined

  return (
    <>
      <DetailSheet
        open={open}
        onOpenChange={onOpenChange}
        width="xl"
        header={
          <DetailHeader
            title={displayTitle(detail, t)}
            meta={[
              detail.cve || detail.ruleId,
              where,
              <FindingAssetName key="asset" id={asset?.id} name={asset?.name} />,
            ]}
            menu={menu}
            onClose={() => onOpenChange(false)}
            actions={
              <>
                <StatusSelect
                  findingId={detail.id}
                  value={triage.status}
                  subStatusId={triage.subStatusId}
                  allowSubStatusMoves
                  onChange={triage.changeStatus}
                  loading={triage.statusBusy}
                  showCheck
                  disabled={locked}
                />
                <SeveritySelect
                  value={triage.severity}
                  onChange={triage.changeSeverity}
                  loading={triage.severityBusy}
                  disabled={locked || !canRescore || !!detail.pendingSeverityRequest}
                  cvss={detail.cvss}
                  showCheck
                />
                <AssigneeSelect
                  findingId={detail.id}
                  value={
                    triage.assignee
                      ? {
                          id: triage.assignee.id,
                          name: triage.assignee.name,
                          email: triage.assignee.email,
                        }
                      : null
                  }
                  onChange={(u) =>
                    triage.changeAssignee(
                      u ? { id: u.id, name: u.name, email: u.email || '', role: 'analyst' } : null
                    )
                  }
                  loading={triage.assigneeBusy}
                  disabled={locked || !canAssign}
                />
              </>
            }
          />
        }
      >
        {isLoading ? (
          <DrawerBodySkeleton />
        ) : (
          <div className="space-y-4">
            {taskNav && (
              <nav
                aria-label={t('remediationHub.drawer.nav', 'Findings of this task')}
                className="flex items-center justify-between gap-2"
              >
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!taskNav.onPrev}
                  onClick={taskNav.onPrev}
                  aria-label={t('remediationHub.drawer.prev', 'Previous finding')}
                >
                  <ChevronLeft className="h-4 w-4" aria-hidden />
                </Button>
                <span className="text-muted-foreground text-xs" aria-live="polite">
                  {t('remediationHub.drawer.position', 'Finding {index} of {total}', {
                    index: String(taskNav.index),
                    total: String(taskNav.total),
                  })}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!taskNav.onNext}
                  onClick={taskNav.onNext}
                  aria-label={t('remediationHub.drawer.next', 'Next finding')}
                >
                  <ChevronRight className="h-4 w-4" aria-hidden />
                </Button>
              </nav>
            )}
            <FindingApprovalBand findingId={detail.id} />
            <FindingWhyItMatters finding={detail} compact />
            {!taskNav && <FindingTaskBand findingId={detail.id} />}
            <FindingFixCard finding={detail} compact onOpenPlan={() => openPage('remediation')} />
            <DetailSections>
              <FindingTypePanel
                finding={detail}
                onOpenTrace={() => openPage('attack-path')}
                onOpenEvidence={() => openPage('evidence')}
              />
              <FindingProperties finding={detail} triage={triage} hideTriage />
              {showDrawerCodeLocation(detail) && (
                <FindingCodeLocation location={codeLocationOf(detail)} compact />
              )}
              <FindingIntelSection finding={detail} />
              <FindingProvenanceSection finding={detail} />
              <FindingIdentitySection findingId={detail.id} />
              <VerificationPanel findingId={detail.id} />
              <FindingRetestSection finding={{ ...detail, status: triage.status }} />
              <FindingRetestCheckSection finding={detail} />
              <FindingTenableRescanSection finding={detail} />
              <FindingIssueGroupSection findingId={detail.id} />

              {description.text && (
                <DetailSection
                  title={t('findings.drawer.description', 'Description')}
                  icon={FileText}
                >
                  <AdvisoryText text={description.text} />
                </DetailSection>
              )}

              {decided.length > 0 && (
                <DetailSection
                  title={t('findings.drawer.approvalHistory', 'Approval history')}
                  icon={ShieldCheck}
                  count={decided.length}
                >
                  <ul className="space-y-2">
                    {decided.map((a: ApiApproval) => (
                      <li key={a.id} className="space-y-1 rounded-md border p-2.5 text-xs">
                        <div className="flex items-center justify-between">
                          <Badge variant="outline" className="text-[11px]">
                            {t(
                              `findings.approvals.status.${a.status}`,
                              APPROVAL_STATUS_CONFIG[a.status as ApprovalStatus]?.label ?? a.status
                            )}
                          </Badge>
                          <time
                            dateTime={a.created_at}
                            title={formatAbsoluteTime(a.created_at, locale)}
                            className="text-muted-foreground"
                          >
                            {formatRelativeTime(a.created_at, locale)}
                          </time>
                        </div>
                        <p className="text-muted-foreground">
                          {t('findings.drawer.requested', 'Requested:')}{' '}
                          <span className="font-medium text-foreground">
                            {(() => {
                              const cfg = FINDING_STATUS_CONFIG[a.requested_status as FindingStatus]
                              return cfg ? t(cfg.labelKey, cfg.label) : a.requested_status
                            })()}
                          </span>
                        </p>
                        <AIProposalBadge approval={a} />
                        {/* Member text: plain, capped and bidi-isolated, so a
                            right-to-left override cannot change how it reads. */}
                        {a.justification && (
                          <p
                            dir="auto"
                            className="line-clamp-2 text-muted-foreground [unicode-bidi:isolate]"
                          >
                            {toDisplayText(a.justification, 500)}
                          </p>
                        )}
                        {a.rejection_reason && (
                          <p className="line-clamp-2 text-destructive">
                            {t('findings.drawer.reason', 'Reason:')}{' '}
                            <span dir="auto" className="[unicode-bidi:isolate]">
                              {toDisplayText(a.rejection_reason, 500)}
                            </span>
                          </p>
                        )}
                      </li>
                    ))}
                  </ul>
                </DetailSection>
              )}
            </DetailSections>

            <FindingActivity
              ref={activityRef}
              findingId={finding.id}
              subject={detail.title}
              enabled={open}
              urlParam={false}
            />

            <DetailSheetFooter>
              <Button className="w-full" onClick={() => openPage()}>
                <ExternalLink className="h-4 w-4" />
                {t('findings.drawer.openFullDetails', 'Open full details')}
              </Button>
            </DetailSheetFooter>
          </div>
        )}
      </DetailSheet>

      {canCreateTicket && (
        <CreateTicketDialog
          findingId={finding.id}
          findingTitle={detail.title}
          open={ticketOpen}
          onOpenChange={setTicketOpen}
        />
      )}
      {triage.dialogs}
    </>
  )
}
