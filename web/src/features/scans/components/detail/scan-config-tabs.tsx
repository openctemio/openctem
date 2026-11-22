'use client'

/**
 * The scan page's Configuration and Details tabs: the scan's own properties
 * on the detail kit (`DetailSectionBlock` + `PropertyList`), with the
 * schedule preview under the schedule rows.
 */

import { useState } from 'react'
import { Tag } from 'lucide-react'

import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import {
  DetailSectionBlock,
  DetailSectionList,
  PropertyGroup,
  PropertyList,
  PropertyRow,
} from '@/features/shared/components/detail'
import { DetailCopyId } from '@/features/shared/components/detail-sheet'
import { TruncatedText } from '@/features/shared/components/truncated-text'
import {
  SCAN_CONFIG_STATUS_LABELS,
  SCAN_TYPE_LABELS,
  SCHEDULE_TYPE_LABELS,
  type ScanConfig,
} from '@/lib/api/scan-types'
import { useAssetGroup } from '@/lib/api/security-hooks'
import { Can, Permission } from '@/lib/permissions'
import { IntensityBadge } from '../intensity-badge'
import { SchedulePreview } from '../schedule-preview'
import { formatScanDate } from '../../lib/format'
import { schedulePreviewRequestFromConfig } from '../../lib/schedule-preview'

/**
 * An asset group by name (scoped read: a group the viewer cannot see shows
 * its short id, never an error).
 */
function AssetGroupName({ id }: { id: string }) {
  const { t } = useTranslation()
  const { data } = useAssetGroup(id, { shouldRetryOnError: false, onError: () => {} })
  const name = (data as { name?: string } | undefined)?.name
  return (
    <Badge variant="outline" className="max-w-[16rem]">
      <TruncatedText value={name || `${id.slice(0, 8)}…`} label={t('scanDetail.asset.groupAria')} />
    </Badge>
  )
}

/** Direct targets: the first few, then all of them on request. */
function TargetList({ targets }: { targets: string[] }) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const shown = all ? targets : targets.slice(0, 12)
  return (
    <div className="min-w-0 space-y-2 py-1.5">
      <div className="flex flex-wrap gap-1.5">
        {shown.map((target, i) => (
          <Badge key={i} variant="secondary" className="max-w-[20rem] font-normal">
            <TruncatedText value={target} label={t('scanDetail.target.label')} />
          </Badge>
        ))}
      </div>
      {targets.length > 12 && (
        <Button variant="link" size="sm" onClick={() => setAll(!all)}>
          {all
            ? t('scanDetail.target.showFewer')
            : t('scanDetail.target.showAll', 'Show all {count}', { count: targets.length })}
        </Button>
      )}
    </div>
  )
}

export function ScanConfigurationTab({ config }: { config: ScanConfig }) {
  const { t } = useTranslation()
  const groupIds =
    config.asset_group_ids && config.asset_group_ids.length > 0
      ? config.asset_group_ids
      : config.asset_group_id
        ? [config.asset_group_id]
        : []
  const targets = config.targets ?? []
  const tags = config.tags ?? []

  return (
    <DetailSectionList>
      <DetailSectionBlock title={t('scanDetail.cfg.schedule')}>
        <PropertyList label={t('scanDetail.cfg.schedule')}>
          <PropertyGroup>
            <PropertyRow label={t('scanDetail.cfg.frequency')}>
              {t(
                `scans.scheduleType.${config.schedule_type}`,
                SCHEDULE_TYPE_LABELS[config.schedule_type]
              )}
            </PropertyRow>
            <PropertyRow label={t('scanDetail.cfg.time')}>{config.schedule_time}</PropertyRow>
            <PropertyRow label={t('scanDetail.cfg.timezone')}>
              {config.schedule_timezone}
            </PropertyRow>
            <PropertyRow label={t('scanDetail.cfg.nextRun')}>
              {config.next_run_at ? formatScanDate(config.next_run_at) : null}
            </PropertyRow>
            <PropertyRow label={t('scanDetail.cfg.rule')}>
              {config.schedule_rrule ? (
                <code className="text-xs break-all">{config.schedule_rrule}</code>
              ) : null}
            </PropertyRow>
          </PropertyGroup>
        </PropertyList>
        <div className="mt-3">
          <SchedulePreview
            request={schedulePreviewRequestFromConfig(config)}
            paused={config.status !== 'active'}
          />
        </div>
      </DetailSectionBlock>

      <DetailSectionBlock title={t('scanDetail.cfg.execution')}>
        <PropertyList label={t('scanDetail.cfg.execution')}>
          <PropertyGroup>
            <PropertyRow label={t('scanDetail.cfg.scanType')}>
              {t(`scans.scanType.${config.scan_type}`, SCAN_TYPE_LABELS[config.scan_type])}
            </PropertyRow>
            <PropertyRow label={t('scans.intensity.label')}>
              <IntensityBadge intensity={config.intensity} />
            </PropertyRow>
            <PropertyRow label={t('scanDetail.cfg.sensorPreference')}>
              {t(`scans.sensorPrefRun.${config.sensor_preference || 'auto'}.label`)}
            </PropertyRow>
            <PropertyRow label={t('scanDetail.cfg.targetsPerJob')}>
              {String(config.targets_per_job ?? '')}
            </PropertyRow>
          </PropertyGroup>
        </PropertyList>
      </DetailSectionBlock>

      {(groupIds.length > 0 || targets.length > 0) && (
        <DetailSectionBlock title={t('scanDetail.cfg.assetGroupsTitle')}>
          <PropertyList label={t('scanDetail.cfg.assetGroupsTitle')}>
            <PropertyGroup className="[&_dl]:grid-cols-1">
              {groupIds.length > 0 && (
                <PropertyRow
                  top
                  label={
                    groupIds.length === 1
                      ? t('scanDetail.asset.group')
                      : t('scanDetail.asset.groups')
                  }
                >
                  <span className="flex flex-wrap gap-1.5 py-1.5">
                    {groupIds.map((id) => (
                      <AssetGroupName key={id} id={id} />
                    ))}
                  </span>
                </PropertyRow>
              )}
              {targets.length > 0 && (
                <PropertyRow
                  top
                  label={t('scanDetail.cfg.directTargets', 'Direct targets ({count})', {
                    count: targets.length,
                  })}
                >
                  <TargetList targets={targets} />
                </PropertyRow>
              )}
            </PropertyGroup>
          </PropertyList>
        </DetailSectionBlock>
      )}

      {tags.length > 0 && (
        <DetailSectionBlock title={t('scanDetail.cfg.tags')} count={tags.length}>
          <div className="flex flex-wrap gap-1.5">
            {tags.map((tag) => (
              <Badge key={tag} variant="secondary" className="max-w-[16rem] gap-1">
                <Tag className="h-3 w-3 shrink-0" aria-hidden />
                <TruncatedText value={tag} label={t('scanDetail.cfg.tag')} />
              </Badge>
            ))}
          </div>
        </DetailSectionBlock>
      )}
    </DetailSectionList>
  )
}

export function ScanDetailsTab({ config }: { config: ScanConfig }) {
  const { t } = useTranslation()
  return (
    <DetailSectionList>
      {config.description && (
        <DetailSectionBlock title={t('scanDetail.details.description')}>
          <p
            dir="auto"
            className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground [unicode-bidi:isolate]"
          >
            {config.description}
          </p>
        </DetailSectionBlock>
      )}
      <DetailSectionBlock title={t('scanDetail.details.about', 'About this scan')}>
        <PropertyList label={t('scanDetail.details.about', 'About this scan')}>
          <PropertyGroup caption={t('scanDetail.details.timeline')}>
            <PropertyRow label={t('scanDetail.details.created')}>
              {formatScanDate(config.created_at)}
            </PropertyRow>
            <PropertyRow label={t('scanDetail.details.lastRun')}>
              {config.last_run_at
                ? formatScanDate(config.last_run_at)
                : t('scanDetail.details.never')}
            </PropertyRow>
            <PropertyRow label={t('scanDetail.details.status')}>
              {t(`scans.configStatus.${config.status}`, SCAN_CONFIG_STATUS_LABELS[config.status])}
            </PropertyRow>
          </PropertyGroup>
          <PropertyGroup caption={t('scanDetail.details.identity')}>
            <PropertyRow label={t('scanDetail.details.createdBy')}>
              {config.created_by_name || t('scanDetail.details.system')}
            </PropertyRow>
            <PropertyRow label={t('scanDetail.details.scanId')}>
              <DetailCopyId id={config.id} label={t('scanDetail.details.scanId')} />
            </PropertyRow>
            {config.scan_workflow_id && (
              <PropertyRow top label={t('scanDetail.details.workflow')}>
                <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 py-1.5">
                  <Can permission={Permission.ScanWorkflowsRead}>
                    <Link
                      href={`/scans/workflows/${encodeURIComponent(config.scan_workflow_id)}`}
                      className="text-sm font-medium text-primary hover:underline"
                    >
                      {t('scanDetail.details.openWorkflow')}
                    </Link>
                  </Can>
                  <DetailCopyId
                    id={config.scan_workflow_id}
                    label={t('scanDetail.details.workflowId')}
                  />
                </div>
              </PropertyRow>
            )}
          </PropertyGroup>
        </PropertyList>
      </DetailSectionBlock>
    </DetailSectionList>
  )
}
