'use client'

/**
 * A scan configuration in the shared detail drawer (sensor drawer layout):
 * state and the run controls in the header, the run record as numbers, the
 * schedule and targets in their own tabs.
 */

import { useMemo, useState } from 'react'
import { Hash, Loader2, Pause, Play, RefreshCw, Tag, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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
  StatusBadge,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'
import { post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import { invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import {
  SCAN_CONFIG_STATUS_LABELS,
  SCAN_TYPE_LABELS,
  SCHEDULE_TYPE_LABELS,
  type ScanConfig,
} from '@/lib/api/scan-types'
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, useHasPermission } from '@/lib/permissions'
import { formatScanDate, scanSuccessRate } from '../lib/format'
import { useScanTrigger } from '../hooks/use-scan-trigger'

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
          badges={
            <StatusBadge
              status={
                config.status === 'active'
                  ? 'active'
                  : config.status === 'paused'
                    ? 'pending'
                    : 'inactive'
              }
            />
          }
          meta={[
            SCAN_TYPE_LABELS[config.scan_type],
            SCHEDULE_TYPE_LABELS[config.schedule_type],
            config.last_run_at ? `last run ${formatScanDate(config.last_run_at)}` : 'never run',
          ]}
          actions={<RunControls config={config} />}
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

/** Trigger / pause / resume / enable, by the configuration's state. */
function RunControls({ config }: { config: ScanConfig }) {
  const [busy, setBusy] = useState<'pause' | 'activate' | null>(null)
  // Trigger goes through the shared guard: it asks before a second concurrent
  // run and ignores double clicks (also from the list behind the drawer).
  const { trigger: triggerScan, isTriggering, dialog } = useScanTrigger()
  const triggering = isTriggering(config.id)

  const run = async (
    kind: 'pause' | 'activate',
    request: () => Promise<unknown>,
    done: string,
    failed: string
  ) => {
    setBusy(kind)
    try {
      await request()
      toast.success(done)
      await invalidateScanConfigsCache()
    } catch (error) {
      toast.error(getErrorMessage(error, failed))
    } finally {
      setBusy(null)
    }
  }
  const trigger = () => void triggerScan(config)
  const pause = () =>
    run(
      'pause',
      () => post(scanEndpoints.pause(config.id), {}),
      `Scan "${config.name}" paused`,
      `Failed to pause scan "${config.name}"`
    )
  const activate = () =>
    run(
      'activate',
      () => post(scanEndpoints.activate(config.id), {}),
      `Scan "${config.name}" activated`,
      `Failed to activate scan "${config.name}"`
    )
  const spin = (k: typeof busy) => busy === k && <Loader2 className="h-4 w-4 animate-spin" />
  const triggerSpin = triggering && <Loader2 className="h-4 w-4 animate-spin" />
  const locked = !!busy || triggering

  if (config.status === 'active') {
    return (
      <>
        <Button size="sm" onClick={trigger} disabled={locked} aria-busy={triggering}>
          {triggerSpin || <Play className="h-4 w-4" />}
          Trigger
        </Button>
        <Button size="sm" variant="outline" onClick={pause} disabled={locked}>
          {spin('pause') || <Pause className="h-4 w-4" />}
          Pause
        </Button>
        {dialog}
      </>
    )
  }
  if (config.status === 'paused') {
    return (
      <>
        <Button size="sm" onClick={activate} disabled={locked}>
          {spin('activate') || <Play className="h-4 w-4" />}
          Resume
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={trigger}
          disabled={locked}
          aria-busy={triggering}
        >
          {triggerSpin || <RefreshCw className="h-4 w-4" />}
          Trigger
        </Button>
        {dialog}
      </>
    )
  }
  return (
    <Button size="sm" onClick={activate} disabled={!!busy}>
      {spin('activate') || <Play className="h-4 w-4" />}
      Enable
    </Button>
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
          caption={SCAN_CONFIG_STATUS_LABELS[config.status]}
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
                    <Badge key={i} variant="secondary" className="text-xs break-all" title={target}>
                      {target.length > 30 ? `${target.slice(0, 30)}…` : target}
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
