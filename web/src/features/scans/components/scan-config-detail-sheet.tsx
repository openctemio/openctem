'use client'

/**
 * A scan configuration in the shared detail drawer (sensor drawer layout):
 * state and the run controls in the header, the run record as numbers, the
 * schedule and targets in their own tabs.
 */

import { useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
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
import type { ScanConfig } from '@/lib/api/scan-types'
import { scanTypeName, scheduleTypeName } from '../lib/labels'
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, useHasPermission } from '@/lib/permissions'
import { formatScanDate, scanSuccessRate } from '../lib/format'
import { schedulePreviewRequestFromConfig } from '../lib/schedule-preview'
import { SchedulePreview } from './schedule-preview'
import { describeTargetOptions, hasCidrTarget, hasDynamicTargets } from '../lib/dynamic-targets'

type Tab = 'overview' | 'config' | 'details'
const TAB_KEYS: { value: Tab; key: string }[] = [
  { value: 'overview', key: 'scans.sheet.overview' },
  { value: 'config', key: 'scans.sheet.configuration' },
  { value: 'details', key: 'scans.sheet.details' },
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
  const { t } = useTranslation()
  const tabs: DetailTab<Tab>[] = TAB_KEYS.map((x) => ({ value: x.value, label: t(x.key) }))
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
      label: t('scans.sheet.copyId'),
      icon: Hash,
      onSelect: () => {
        copyToClipboard(config.id)
        toast.success(t('scans.sheet.idCopied'))
      },
    },
  ]
  if (canDelete) {
    menu.push({
      label: t('scans.sheet.deleteConfig'),
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
            scanTypeLabel(config, t).label,
            scheduleTypeName(t, config.schedule_type),
            scanStateLabel(config, t),
          ]}
          actions={<ScanControls config={config} />}
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
      tabs={<DetailTabs tabs={tabs} value={tab} onValueChange={setTab} />}
    >
      {tab === 'overview' && <Overview config={config} />}
      {tab === 'config' && <Configuration config={config} />}
      {tab === 'details' && <Details config={config} />}
    </DetailSheet>
  )
}

function Overview({ config }: { config: ScanConfig }) {
  const { t } = useTranslation()
  // The same formula as the scan list and the scan page (scanSuccessRate).
  const successRate = useMemo(() => scanSuccessRate(config), [config])
  const settled = config.successful_runs + (config.partial_runs ?? 0) + config.failed_runs
  return (
    <div className="space-y-5">
      <DetailStatGrid aria-label={t('scans.sheet.keyNumbers')}>
        <DetailStat
          label={t('scans.sheet.successRate')}
          value={successRate === null ? t('scans.sheet.noRuns') : `${successRate}%`}
          meter={
            successRate === null
              ? undefined
              : {
                  value: config.successful_runs,
                  max: settled,
                  label: t('scans.sheet.successfulRuns'),
                }
          }
          caption={scanStateLabel(config, t)}
        />
        <DetailStat label={t('scans.sheet.totalRuns')} value={config.total_runs} />
        <DetailStat label={t('scans.sheet.successful')} value={config.successful_runs} />
        <DetailStat label={t('scans.sheet.partial')} value={config.partial_runs ?? 0} />
        <DetailStat
          label={t('scans.sheet.failed')}
          value={config.failed_runs}
          tone={config.failed_runs > 0 ? 'destructive' : 'default'}
        />
      </DetailStatGrid>

      <DetailSections>
        {config.description && (
          <DetailSection title={t('scans.sheet.description')}>
            <p className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground">
              {config.description}
            </p>
          </DetailSection>
        )}
        <DetailSection title={t('scans.sheet.timeline')}>
          <DetailFieldGrid>
            <DetailField label={t('scans.sheet.created')}>
              {formatScanDate(config.created_at)}
            </DetailField>
            {config.last_run_at && (
              <DetailField label={t('scans.sheet.lastRun')}>
                {formatScanDate(config.last_run_at)}
              </DetailField>
            )}
            {config.next_run_at && (
              <DetailField label={t('scans.sheet.nextScheduled')}>
                {formatScanDate(config.next_run_at)}
              </DetailField>
            )}
          </DetailFieldGrid>
        </DetailSection>
      </DetailSections>
    </div>
  )
}

function Configuration({ config }: { config: ScanConfig }) {
  const { t } = useTranslation()
  return (
    <DetailSections>
      <DetailSection title={t('scans.sheet.schedule')}>
        <DetailFieldGrid>
          <DetailField label={t('scans.sheet.scanType')}>
            {scanTypeName(t, config.scan_type)}
          </DetailField>
          <DetailField label={t('scans.sheet.frequency')}>
            {scheduleTypeName(t, config.schedule_type)}
          </DetailField>
          {config.schedule_rrule && (
            <DetailField label={t('scans.sheet.rule')} full>
              <code className="text-xs break-all">{config.schedule_rrule}</code>
            </DetailField>
          )}
          {config.schedule_time && (
            <DetailField label={t('scans.sheet.time')}>{config.schedule_time}</DetailField>
          )}
          <DetailField label={t('scans.sheet.timezone')}>{config.schedule_timezone}</DetailField>
        </DetailFieldGrid>
        <div className="mt-4">
          <SchedulePreview
            request={schedulePreviewRequestFromConfig(config)}
            paused={config.status !== 'active'}
          />
        </div>
      </DetailSection>
      {config.tags && config.tags.length > 0 && (
        <DetailSection title={t('scans.sheet.tags')} count={config.tags.length}>
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
  const { t } = useTranslation()
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
        <DetailSection title={t('scans.sheet.targets')}>
          <DetailFieldGrid>
            {groupIds.length > 0 && (
              <DetailField
                label={
                  groupIds.length === 1 ? t('scans.sheet.assetGroup') : t('scans.sheet.assetGroups')
                }
                full
              >
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
              <DetailField
                label={t('scans.sheet.directTargets', undefined, { count: targets.length })}
                full
              >
                <span className="flex flex-wrap gap-1">
                  {targets.slice(0, 5).map((target, i) => (
                    <Badge key={i} variant="secondary" className="max-w-[16rem] text-xs">
                      <TruncatedText value={target} label={t('scans.sheet.target')} />
                    </Badge>
                  ))}
                  {targets.length > 5 && (
                    <Badge variant="secondary" className="text-xs">
                      {t('scans.sheet.moreTargets', undefined, { count: targets.length - 5 })}
                    </Badge>
                  )}
                </span>
              </DetailField>
            )}
            {(hasDynamicTargets(targets, config.target_options) || hasCidrTarget(targets)) && (
              <DetailField label={t('scans.sheet.dynamicTargets')} full>
                <span className="block text-sm" data-testid="scan-dynamic-targets">
                  {hasDynamicTargets(targets, config.target_options)
                    ? config.schedule_type === 'manual'
                      ? t('scans.sheet.dynManual')
                      : t('scans.sheet.dynScheduled')
                    : t('scans.sheet.dynRanges')}
                </span>
                {describeTargetOptions(targets, config.target_options, t).length > 0 && (
                  <span className="block text-xs text-muted-foreground">
                    {describeTargetOptions(targets, config.target_options, t).join(' · ')}
                  </span>
                )}
              </DetailField>
            )}
          </DetailFieldGrid>
        </DetailSection>
      )}
      <DetailSection title={t('scans.sheet.identity')}>
        <DetailFieldGrid>
          <DetailField label={t('scans.sheet.createdBy')}>
            {config.created_by_name || t('scans.sheet.system')}
          </DetailField>
          <DetailField label={t('scans.sheet.created')}>
            {formatScanDate(config.created_at)}
          </DetailField>
          <DetailField label={t('scans.sheet.idLabel')} full>
            <DetailCopyId id={config.id} label={t('scans.sheet.configId')} />
          </DetailField>
        </DetailFieldGrid>
      </DetailSection>
    </DetailSections>
  )
}
