'use client'

/**
 * What a member holds (access) and owns (work) in this organization (RFC-050
 * member lifecycle). Shown in the member drawer and in the offboarding wizard.
 * The backend computes it; this only renders.
 */

import { CalendarClock, KeyRound, Shield, Swords, Users, Workflow } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailChipList, DetailSection, DetailStat, DetailStatGrid } from '@/features/shared'
import type { LifecycleRef, MemberAccessReport } from '../types/member.types'
import { ownedScheduleCount } from '../lib/member-lifecycle'

function chips(refs: LifecycleRef[] | undefined, withDetail = true) {
  return (refs ?? []).map((r) => ({
    key: r.id,
    label: r.name,
    muted: r.status === 'inactive' || r.status === 'paused' || r.status === 'suspended',
    meta: withDetail && r.detail ? r.detail : undefined,
    tag: r.status && r.status !== 'active' ? r.status : undefined,
  }))
}

export interface MemberAccessReportViewProps {
  report: MemberAccessReport | undefined
  isLoading?: boolean
  /** Hide the "Holds" part (the wizard shows only what must be reassigned). */
  ownedOnly?: boolean
}

export function MemberAccessReportView({
  report,
  isLoading,
  ownedOnly = false,
}: MemberAccessReportViewProps) {
  if (isLoading) {
    return (
      <div className="space-y-2" aria-busy="true" aria-label="Loading access report">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    )
  }
  if (!report) return null

  const schedules = [
    ...chips(report.owned_scans),
    ...chips(report.owned_report_schedules),
    ...chips(report.owned_workflows, false),
  ]

  return (
    <div className="space-y-5" data-testid="member-access-report">
      {!ownedOnly && (
        <>
          <DetailStatGrid aria-label="Access summary">
            <DetailStat
              label="Visible assets"
              value={report.visible_assets}
              caption={report.status === 'suspended' ? 'none while disabled' : undefined}
            />
            <DetailStat label="Direct grants" value={report.direct_grants} />
            <DetailStat label="Access groups" value={report.groups?.length ?? 0} />
            <DetailStat label="API keys" value={report.api_keys?.length ?? 0} />
          </DetailStatGrid>
          <DetailSection title="Roles" icon={Shield} count={report.roles?.length ?? 0}>
            <DetailChipList chips={chips(report.roles, false)} label="Roles" />
          </DetailSection>
          <DetailSection title="Access groups" icon={Users} count={report.groups?.length ?? 0}>
            <DetailChipList chips={chips(report.groups)} label="Access groups" />
          </DetailSection>
          <DetailSection title="API keys" icon={KeyRound} count={report.api_keys?.length ?? 0}>
            <DetailChipList chips={chips(report.api_keys)} label="API keys" />
          </DetailSection>
          <DetailSection
            title="Pentest engagements"
            icon={Swords}
            count={report.campaigns?.length ?? 0}
          >
            <DetailChipList chips={chips(report.campaigns)} label="Pentest engagements" />
          </DetailSection>
        </>
      )}
      <DetailSection title="Owned schedules" icon={CalendarClock} count={ownedScheduleCount(report)}>
        <DetailChipList chips={schedules} label="Owned schedules" />
      </DetailSection>
      <DetailStatGrid aria-label="Owned work">
        <DetailStat label="Open assigned findings" value={report.assigned_findings} />
        <DetailStat label="Owned assets" value={report.owned_assets} />
      </DetailStatGrid>
      {!ownedOnly && report.status === 'suspended' && (
        <p className="flex items-center gap-2 text-xs text-muted-foreground">
          <Workflow className="h-3.5 w-3.5" />
          Disabled: groups, grants and ownership are kept frozen until the member is re-enabled or
          offboarded.
        </p>
      )}
    </div>
  )
}
