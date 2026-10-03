'use client'

/**
 * One scanner run (a scan session) in the shared detail drawer: target and
 * state in the header, what went wrong first, the findings as numbers, the
 * scanner and target details in their own tab.
 */

import { useState } from 'react'
import Link from 'next/link'
import { CircleAlert, Eye, Hash, Shield } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DetailCallout,
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  DetailTabs,
  EmptyState,
  RunStatusBadge,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'
import type { ScanSession } from '@/lib/api/scan-types'
import { copyToClipboard } from '@/lib/clipboard'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'
import { formatScanDate, formatScanDuration } from '../lib/format'

type Tab = 'overview' | 'findings' | 'details'
const TABS: DetailTab<Tab>[] = [
  { value: 'overview', label: 'Overview' },
  { value: 'findings', label: 'Findings' },
  { value: 'details', label: 'Details' },
]

export interface ScanSessionDetailSheetProps {
  session: ScanSession | null
  onOpenChange: (open: boolean) => void
}

export function ScanSessionDetailSheet({ session, onOpenChange }: ScanSessionDetailSheetProps) {
  const [tab, setTab] = useState<Tab>('overview')
  const [shownId, setShownId] = useState<string | null>(null)
  if (session && session.id !== shownId) {
    setShownId(session.id)
    setTab('overview')
  }
  if (!session) return null

  const scanner = [session.scanner_name, session.scanner_version && `v${session.scanner_version}`]
    .filter(Boolean)
    .join(' ')
  const menu: DetailMenuItem[] = [
    {
      label: 'Copy ID',
      icon: Hash,
      onSelect: () => {
        copyToClipboard(session.id)
        toast.success('Session ID copied to clipboard')
      },
    },
  ]

  return (
    <DetailSheet
      open
      onOpenChange={onOpenChange}
      panel={tab}
      header={
        <DetailHeader
          title={session.asset_value}
          badges={<RunStatusBadge status={session.status} />}
          meta={[
            session.asset_type,
            scanner,
            session.duration_ms
              ? formatScanDuration(session.duration_ms)
              : session.status === 'running'
                ? 'in progress'
                : null,
          ]}
          actions={
            session.status === 'completed' && session.findings_total > 0 ? (
              <Button asChild size="sm">
                <Link href={`/findings?scan_id=${session.id}`}>
                  <Eye className="h-4 w-4" />
                  View {session.findings_total} findings
                </Link>
              </Button>
            ) : undefined
          }
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
      tabs={<DetailTabs tabs={TABS} value={tab} onValueChange={setTab} />}
    >
      {tab === 'overview' && <Overview session={session} />}
      {tab === 'findings' && <Findings session={session} />}
      {tab === 'details' && <Details session={session} />}
    </DetailSheet>
  )
}

function Overview({ session }: { session: ScanSession }) {
  const sev = session.findings_by_severity ?? {}
  const rows = [
    ['critical', 'Critical', sev.critical ?? 0],
    ['high', 'High', sev.high ?? 0],
    ['medium', 'Medium', sev.medium ?? 0],
    ['low', 'Low', sev.low ?? 0],
  ] as const
  return (
    <div className="space-y-5">
      {session.error_message && (
        <DetailCallout tone="destructive" icon={CircleAlert} title="Run failed" label="Run failed">
          <span className="block font-mono text-xs whitespace-pre-wrap">
            {session.error_message}
          </span>
        </DetailCallout>
      )}

      <DetailStatGrid aria-label="Key numbers">
        <DetailStat label="Findings" value={session.findings_total} />
        <DetailStat
          label="New"
          value={session.findings_new}
          tone={session.findings_new > 0 ? 'warning' : 'default'}
        />
        {session.findings_fixed > 0 && (
          <DetailStat label="Fixed since last scan" value={session.findings_fixed} />
        )}
        {session.duration_ms ? (
          <DetailStat label="Duration" value={formatScanDuration(session.duration_ms)} />
        ) : null}
      </DetailStatGrid>

      <DetailSections>
        {session.findings_total > 0 && (
          <DetailSection title="Findings by severity">
            <ul className="space-y-2">
              {rows.map(([level, label, count]) => (
                <li key={level} className="flex items-center gap-3 text-sm">
                  <span
                    aria-hidden
                    className={cn('h-2 w-2 rounded-full', SEVERITY_DOT_COLORS[level])}
                  />
                  <span className="flex-1">{label}</span>
                  <span className="font-semibold tabular-nums">{count}</span>
                </li>
              ))}
            </ul>
          </DetailSection>
        )}
        <DetailSection title="Timeline">
          <DetailFieldGrid>
            <DetailField label="Created">{formatScanDate(session.created_at)}</DetailField>
            {session.started_at && (
              <DetailField label="Started">{formatScanDate(session.started_at)}</DetailField>
            )}
            {session.completed_at && (
              <DetailField label={session.status === 'completed' ? 'Completed' : 'Ended'}>
                {formatScanDate(session.completed_at)}
              </DetailField>
            )}
          </DetailFieldGrid>
        </DetailSection>
      </DetailSections>
    </div>
  )
}

function Findings({ session }: { session: ScanSession }) {
  if (session.findings_total === 0) {
    return (
      <EmptyState
        icon={Shield}
        title="No findings"
        description={
          session.status === 'completed'
            ? 'This run detected no vulnerabilities.'
            : 'The run is still in progress or has not started yet.'
        }
      />
    )
  }
  return (
    <DetailSection title="Findings summary">
      <p className="text-sm text-muted-foreground">
        {session.findings_total} vulnerabilities detected on {session.asset_value}.
        {session.findings_new > 0 && ` ${session.findings_new} are new.`}
      </p>
      <Button asChild size="sm" className="w-full">
        <Link href={`/findings?scan_id=${session.id}`}>View all findings</Link>
      </Button>
    </DetailSection>
  )
}

function Details({ session }: { session: ScanSession }) {
  return (
    <DetailSections>
      <DetailSection title="Scanner">
        <DetailFieldGrid>
          <DetailField label="Scanner">{session.scanner_name}</DetailField>
          {session.scanner_version && (
            <DetailField label="Version">
              <Badge variant="outline">{session.scanner_version}</Badge>
            </DetailField>
          )}
          {session.scanner_type && (
            <DetailField label="Type">
              <span className="capitalize">{session.scanner_type}</span>
            </DetailField>
          )}
        </DetailFieldGrid>
      </DetailSection>
      <DetailSection title="Target">
        <DetailFieldGrid>
          <DetailField label="Asset type">
            <span className="capitalize">{session.asset_type}</span>
          </DetailField>
          <DetailField label="Target" full>
            <span className="break-all">{session.asset_value}</span>
          </DetailField>
          {session.branch && (
            <DetailField label="Branch">
              <Badge variant="secondary">{session.branch}</Badge>
            </DetailField>
          )}
          {session.commit_sha && (
            <DetailField label="Commit">
              <code className="font-mono text-xs" title={session.commit_sha}>
                {session.commit_sha.substring(0, 7)}
              </code>
            </DetailField>
          )}
        </DetailFieldGrid>
      </DetailSection>
      <DetailSection title="Identity">
        <DetailFieldGrid>
          {session.sensor_id && (
            <DetailField label="Sensor ID" full>
              <DetailCopyId id={session.sensor_id} label="Sensor ID" />
            </DetailField>
          )}
          {session.duration_ms ? (
            <DetailField label="Duration">{formatScanDuration(session.duration_ms)}</DetailField>
          ) : null}
          <DetailField label="Run ID" full>
            <DetailCopyId id={session.id} label="Run ID" />
          </DetailField>
        </DetailFieldGrid>
      </DetailSection>
    </DetailSections>
  )
}
