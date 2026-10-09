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
import { ExternalLink, FileText, Link2, ShieldCheck, Ticket } from 'lucide-react'
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
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import type { Severity } from '@/features/shared/types'
import { useFindingApi, useFindingApprovals } from '../api/use-findings-api'
import { useFindingTriage } from '../hooks/use-finding-triage'
import { findingDescription, findingSourceLabel, toFindingDetail } from '../lib/finding-detail'
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
import { SeveritySelect } from './severity-select'
import { useCanMutate } from '@/lib/permissions'
import { StatusSelect } from './status-select'
import { FindingWhyItMatters } from './detail/finding-why-it-matters'
import { FindingFixCard } from './detail/finding-fix-card'
import { FindingProperties } from './detail/finding-properties'
import { FindingRetestSection } from './detail/finding-retest'
import { FindingActivity } from './finding-activity'
import type { EntityActivityHandle } from '@/features/activity/components/entity-activity'

interface FindingDetailDrawerProps {
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
}: FindingDetailDrawerProps) {
  const router = useRouter()
  const integrationsEnabled = useModuleEnabled('integrations')
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
  const triage = useFindingTriage(
    detail ?? { id: '', status: 'new', severity: 'medium', assignee: undefined },
    {
      onStatusChange: (s) => finding && onStatusChange?.(finding.id, s),
      onSeverityChange: (s) => finding && onSeverityChange?.(finding.id, s),
      onAssigneeChange: (u) => finding && onAssigneeChange?.(finding.id, u),
    }
  )

  const { data: approvals } = useFindingApprovals(
    open && finding && ['false_positive', 'accepted'].includes(triage.status)
      ? finding.id
      : undefined
  )

  const openPage = useCallback(
    (tab?: string) => {
      if (!finding) return
      onOpenChange(false)
      router.push(`/findings/${finding.id}${tab ? `?tab=${tab}` : ''}`)
    },
    [finding, onOpenChange, router]
  )

  // ⌘/Ctrl+Enter opens the full page; ⌘/Ctrl+C opens the activity panel on
  // its comment box (unless text is selected: then it is a copy).
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && t.tagName !== 'TEXTAREA') {
        e.preventDefault()
        openPage()
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'c' && !e.shiftKey) {
        if (
          t.tagName !== 'TEXTAREA' &&
          t.tagName !== 'INPUT' &&
          !window.getSelection()?.toString()
        ) {
          e.preventDefault()
          activityRef.current?.open({ compose: true })
        }
      }
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
  }, [open, openPage])

  if (!finding || !detail) return null

  const menu: DetailMenuItem[] = [
    {
      label: 'Copy link',
      icon: Link2,
      onSelect: () => {
        void copyToClipboard(`${window.location.origin}/findings/${finding.id}`)
        toast.success('Link copied')
      },
    },
    ...(integrationsEnabled
      ? [{ label: 'Create ticket', icon: Ticket, onSelect: () => setTicketOpen(true) }]
      : []),
  ]

  const asset = detail.assets[0]
  const description = findingDescription(detail)

  return (
    <>
      <DetailSheet
        open={open}
        onOpenChange={onOpenChange}
        width="xl"
        header={
          <DetailHeader
            title={detail.title}
            meta={[findingSourceLabel(detail.source), detail.cve, asset?.name]}
            menu={menu}
            onClose={() => onOpenChange(false)}
            actions={
              <>
                <StatusSelect
                  value={triage.status}
                  onChange={triage.changeStatus}
                  loading={triage.statusBusy}
                  showCheck
                  source={detail.source}
                />
                <SeveritySelect
                  value={triage.severity}
                  onChange={triage.changeSeverity}
                  loading={triage.severityBusy}
                  disabled={!canRescore}
                  cvss={detail.cvss}
                  showCheck
                />
                <AssigneeSelect
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
            <FindingWhyItMatters finding={detail} compact />
            <FindingFixCard finding={detail} compact onOpenPlan={() => openPage('remediation')} />
            <DetailSections>
              <FindingProperties finding={detail} triage={triage} hideTriage />
              <FindingRetestSection finding={{ ...detail, status: triage.status }} />

              {description.text && (
                <DetailSection title="Description" icon={FileText}>
                  <p className="line-clamp-6 text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground">
                    {description.text}
                  </p>
                </DetailSection>
              )}

              {approvals && approvals.length > 0 && (
                <DetailSection title="Approval history" icon={ShieldCheck} count={approvals.length}>
                  <ul className="space-y-2">
                    {approvals.map((a: ApiApproval) => (
                      <li key={a.id} className="space-y-1 rounded-md border p-2.5 text-xs">
                        <div className="flex items-center justify-between">
                          <Badge variant="outline" className="text-[11px]">
                            {APPROVAL_STATUS_CONFIG[a.status as ApprovalStatus]?.label ?? a.status}
                          </Badge>
                          <span className="text-muted-foreground">
                            {new Date(a.created_at).toLocaleDateString('en-US', {
                              month: 'short',
                              day: 'numeric',
                              year: 'numeric',
                            })}
                          </span>
                        </div>
                        <p className="text-muted-foreground">
                          Requested:{' '}
                          <span className="font-medium text-foreground">
                            {FINDING_STATUS_CONFIG[a.requested_status as FindingStatus]?.label ??
                              a.requested_status}
                          </span>
                        </p>
                        {a.justification && (
                          <p className="line-clamp-2 text-muted-foreground">{a.justification}</p>
                        )}
                        {a.rejection_reason && (
                          <p className="line-clamp-2 text-destructive">
                            Reason: {a.rejection_reason}
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
                Open full details
              </Button>
            </DetailSheetFooter>
          </div>
        )}
      </DetailSheet>

      {integrationsEnabled && (
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
