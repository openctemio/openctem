'use client'

/**
 * A scan configuration in the shared detail drawer (sensor drawer layout):
 * state and the run controls in the header, the run record as numbers, the
 * schedule and targets in their own tabs.
 */

import { useMemo, useState } from 'react'
import { Hash, Tag, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import {
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
  TruncatedText,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'
import { LastRunCell } from './last-run-cell'
import { ScanControls, scanStateLabel } from './scan-controls'
import { lastRunOf, scanTypeLabel } from '../lib/scan-status'
import { SCAN_TYPE_LABELS, SCHEDULE_TYPE_LABELS, type ScanConfig } from '@/lib/api/scan-types'
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, useHasPermission } from '@/lib/permissions'
import { formatScanDate, scanSuccessRate } from '../lib/format'
import { schedulePreviewRequestFromConfig } from '../lib/schedule-preview'
import { SchedulePreview } from './schedule-preview'

type Tab = 'overview' | 'config' | 'details'
const TABS: DetailTab<Tab>[] = [
  { value: 'overview', label: 'Overview' },
  { value: 'config', label: 'Configuration' },
  { value: 'details', label: 'Details' },
]

export interface ScanConfigDetailSheetProps {
  config: ScanConfig | null
  onOpenChange: (open: boolean) => void
  /** Opens the page's delete confirmation. */
  onDelete: (config: ScanConfig) => void
}

export function ScanConfigDetailSheet({
  config,
  onOpenChange,
  onDelete,
}: ScanConfigDetailSheetProps) {
  const [tab, setTab] = useState<Tab>('overview')
  const [shownId, setShownId] = useState<string | null>(null)
  if (config && config.id !== shownId) {
    setShownId(config.id)
    setTab('overview')
  }
  const canDelete = useHasPermission(Permission.ScansDelete)
  if (!config) return null

  const menu: DetailMenuItem[] = [
    {
      label: 'Copy ID',
      icon: Hash,
      onSelect: () => {
        copyToClipboard(config.id)
        toast.success('ID copied to clipboard')
      },
    },
  ]
  if (canDelete) {
    menu.push({
      label: 'Delete configuration',
      icon: Trash2,
      destructive: true,
      separatorBefore: true,
      onSelect: () => onDelete(config),
    })
  }

  return (
    <DetailSheet
      open
      onOpenChange={onOpenChange}
      panel={tab}
      header={
        <DetailHeader
          title={config.name}
          badges={<LastRunCell run={lastRunOf(config)} />}
          meta={[
            scanTypeLabel(config).label,
            SCHEDULE_TYPE_LABELS[config.schedule_type],
            scanStateLabel(config),
          ]}
          actions={<ScanControls config={config} />}
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
      tabs={<DetailTabs tabs={TABS} value={tab} onValueChange={setTab} />}
    >
      {tab === 'overview' && <Overview config={config} />}
      {tab === 'config' && <Configuration config={config} />}
      {tab === 'details' && <Details config={config} />}
    </DetailSheet>
  )
}

function Overview({ config }: { config: ScanConfig }) {
  // The same formula as the scan list and the scan page (scanSuccessRate).
  const successRate = useMemo(() => scanSuccessRate(config), [config])
  const settled = config.successful_runs + (config.partial_runs ?? 0) + config.failed_runs
  return (
    <div className="space-y-5">
      <DetailStatGrid aria-label="Key numbers">
        <DetailStat
          label="Success rate"
          value={successRate === null ? 'No runs' : `${successRate}%`}
          meter={
            successRate === null
              ? undefined
              : { value: config.successful_runs, max: settled, label: 'Successful runs' }
          }
          caption={scanStateLabel(config)}
        />
        <DetailStat label="Total runs" value={config.total_runs} />
        <DetailStat label="Successful" value={config.successful_runs} />
        <DetailStat label="Partial" value={config.partial_runs ?? 0} />
        <DetailStat
          label="Failed"
          value={config.failed_runs}
          tone={config.failed_runs > 0 ? 'destructive' : 'default'}
        />
      </DetailStatGrid>

      <DetailSections>
        {config.description && (
          <DetailSection title="Description">
            <p className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground">
              {config.description}
            </p>
          </DetailSection>
        )}
        <DetailSection title="Timeline">
          <DetailFieldGrid>
            <DetailField label="Created">{formatScanDate(config.created_at)}</DetailField>
            {config.last_run_at && (
              <DetailField label="Last run">{formatScanDate(config.last_run_at)}</DetailField>
            )}
            {config.next_run_at && (
              <DetailField label="Next scheduled">{formatScanDate(config.next_run_at)}</DetailField>
            )}
          </DetailFieldGrid>
        </DetailSection>
      </DetailSections>
    </div>
  )
}

function Configuration({ config }: { config: ScanConfig }) {
  return (
    <DetailSections>
      <DetailSection title="Schedule">
        <DetailFieldGrid>
          <DetailField label="Scan type">{SCAN_TYPE_LABELS[config.scan_type]}</DetailField>
          <DetailField label="Frequency">{SCHEDULE_TYPE_LABELS[config.schedule_type]}</DetailField>
          {config.schedule_rrule && (
            <DetailField label="Rule" full>
              <code className="text-xs break-all">{config.schedule_rrule}</code>
            </DetailField>
          )}
          {config.schedule_time && <DetailField label="Time">{config.schedule_time}</DetailField>}
          <DetailField label="Timezone">{config.schedule_timezone}</DetailField>
        </DetailFieldGrid>
        <div className="mt-4">
          <SchedulePreview
            request={schedulePreviewRequestFromConfig(config)}
            paused={config.status !== 'active'}
          />
        </div>
      </DetailSection>
      {config.tags && config.tags.length > 0 && (
        <DetailSection title="Tags" count={config.tags.length}>
          <div className="flex flex-wrap gap-2">
            {config.tags.map((tag) => (
              <Badge key={tag} variant="secondary" className="gap-1">
                <Tag className="h-3 w-3" />
                {tag}
              </Badge>
            ))}
          </div>
        </DetailSection>
      )}
    </DetailSections>
  )
}

function Details({ config }: { config: ScanConfig }) {
  const groupIds =
    config.asset_group_ids && config.asset_group_ids.length > 0
      ? config.asset_group_ids
      : config.asset_group_id
        ? [config.asset_group_id]
        : []
  const targets = config.targets ?? []
  return (
    <DetailSections>
      {(groupIds.length > 0 || targets.length > 0) && (
        <DetailSection title="Targets">
          <DetailFieldGrid>
            {groupIds.length > 0 && (
              <DetailField label={groupIds.length === 1 ? 'Asset group' : 'Asset groups'} full>
                <span className="flex flex-wrap gap-1">
                  {groupIds.map((id) => (
                    <Badge key={id} variant="outline" className="font-mono text-xs" title={id}>
                      {id.slice(0, 8)}…
                    </Badge>
                  ))}
                </span>
              </DetailField>
            )}
            {targets.length > 0 && (
              <DetailField label={`Direct targets (${targets.length})`} full>
                <span className="flex flex-wrap gap-1">
                  {targets.slice(0, 5).map((target, i) => (
                    <Badge key={i} variant="secondary" className="max-w-[16rem] text-xs">
                      <TruncatedText value={target} label="Target" />
                    </Badge>
                  ))}
                  {targets.length > 5 && (
                    <Badge variant="secondary" className="text-xs">
                      +{targets.length - 5} more
                    </Badge>
                  )}
                </span>
              </DetailField>
            )}
          </DetailFieldGrid>
        </DetailSection>
      )}
      <DetailSection title="Identity">
        <DetailFieldGrid>
          <DetailField label="Created by">{config.created_by_name || 'System'}</DetailField>
          <DetailField label="Created">{formatScanDate(config.created_at)}</DetailField>
          <DetailField label="ID" full>
            <DetailCopyId id={config.id} label="Configuration ID" />
          </DetailField>
        </DetailFieldGrid>
      </DetailSection>
    </DetailSections>
  )
}
