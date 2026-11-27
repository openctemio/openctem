'use client'

import { capabilitySwatch } from '@/lib/capability-colors'
import { TAG_SWATCH_CLASS } from '@/lib/tag-colors'
import { memo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Globe, Sparkles, Wrench, Bot, ExternalLink } from 'lucide-react'
import Link from '@/components/link'

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
} from '@/features/shared'
import { Skeleton } from '@/components/ui/skeleton'
import { DynamicIcon } from '@/components/dynamic-icon'

import { useCapabilityUsageStats } from '@/lib/api/capability-hooks'
import type { Capability, CapabilityUsageStats } from '@/lib/api/capability-types'

interface CapabilityDetailPanelProps {
  capability: Capability | null
  /** Initial stats from batch API (counts only) for instant display */
  initialStats?: CapabilityUsageStats
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** The names of the tools or sensors using a capability. */
function NameList({
  names,
  icon: Icon,
  empty,
  loading,
}: {
  names?: string[]
  icon: React.ElementType
  empty: string
  loading: boolean
}) {
  if (loading) {
    return (
      <div className="space-y-2" aria-hidden>
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    )
  }
  if (!names || names.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>
  return (
    <ul className="divide-y rounded-lg border">
      {names.map((name) => (
        <li key={name} className="flex items-center gap-2 px-3 py-2 text-sm">
          <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <span className="min-w-0 break-words">{name}</span>
        </li>
      ))}
    </ul>
  )
}

export const CapabilityDetailPanel = memo(function CapabilityDetailPanel({
  capability,
  initialStats,
  open,
  onOpenChange,
}: CapabilityDetailPanelProps) {
  const { t } = useTranslation()
  // Fetch usage stats with full details (includes names)
  const { data: usageStats, isLoading } = useCapabilityUsageStats(open ? capability?.id : null)

  // Use fetched data, fall back to initial stats for instant counts display
  const stats = usageStats || initialStats
  const hasNames = usageStats?.tool_names || usageStats?.sensor_names
  const isLoadingNames = isLoading && !hasNames

  if (!capability) return null

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      width="md"
      header={
        <DetailHeader
          title={capability.display_name}
          badges={
            <>
              {capability.category && (
                <Badge variant="outline" className="text-xs capitalize">
                  {capability.category}
                </Badge>
              )}
              <Badge variant="secondary" className="gap-1 text-xs">
                {capability.is_builtin ? (
                  <Globe className="h-3 w-3" />
                ) : (
                  <Sparkles className="h-3 w-3" />
                )}
                {capability.is_builtin
                  ? t('scans.capabilities.type.platform', 'Platform')
                  : t('scans.capabilities.type.custom', 'Custom')}
              </Badge>
            </>
          }
          meta={[
            <code key="name" className="font-mono">
              {capability.name}
            </code>,
          ]}
          onClose={() => onOpenChange(false)}
        />
      }
    >
      <div className="space-y-5">
        <DetailStatGrid aria-label={t('scans.capabilities.detail.usage', 'Usage')}>
          <DetailStat
            label={t('scans.capabilities.detail.tools', 'Tools')}
            value={stats?.tool_count ?? 0}
          />
          <DetailStat
            label={t('scans.capabilities.detail.sensors', 'Sensors')}
            value={stats?.sensor_count ?? 0}
          />
        </DetailStatGrid>

        <DetailSections>
          {capability.description && (
            <DetailSection title={t('scans.capabilities.detail.description', 'Description')}>
              <p className="text-sm text-muted-foreground">{capability.description}</p>
            </DetailSection>
          )}

          <DetailSection
            title={t('scans.capabilities.detail.tools', 'Tools')}
            icon={Wrench}
            count={stats?.tool_count || undefined}
            actions={
              stats && stats.tool_count > 0 ? (
                <Link
                  href="/settings/scanning/tools"
                  className="flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  {t('scans.capabilities.detail.viewAll', 'View all')}
                  <ExternalLink className="h-3 w-3" />
                </Link>
              ) : undefined
            }
          >
            <NameList
              names={usageStats?.tool_names}
              icon={Wrench}
              empty={t('scans.capabilities.detail.noTools', 'No tools are using this capability.')}
              loading={isLoadingNames}
            />
          </DetailSection>

          <DetailSection
            title={t('scans.capabilities.detail.sensors', 'Sensors')}
            icon={Bot}
            count={stats?.sensor_count || undefined}
            actions={
              stats && stats.sensor_count > 0 ? (
                <Link
                  href="/sensors"
                  className="flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  {t('scans.capabilities.detail.viewAll', 'View all')}
                  <ExternalLink className="h-3 w-3" />
                </Link>
              ) : undefined
            }
          >
            <NameList
              names={usageStats?.sensor_names}
              icon={Bot}
              empty={t(
                'scans.capabilities.detail.noSensors',
                'No sensors have this capability assigned.'
              )}
              loading={isLoadingNames}
            />
          </DetailSection>

          <DetailSection title={t('scans.capabilities.detail.details', 'Details')}>
            <DetailFieldGrid>
              <DetailField label={t('scans.capabilities.detail.codeName', 'Code name')}>
                <span className="font-mono text-xs break-all">{capability.name}</span>
              </DetailField>
              <DetailField label={t('scans.capabilities.col.category', 'Category')}>
                <span className="capitalize">{capability.category || '-'}</span>
              </DetailField>
              <DetailField label={t('scans.capabilities.col.type', 'Type')}>
                {capability.is_builtin
                  ? t('scans.capabilities.type.platform', 'Platform')
                  : t('scans.capabilities.type.custom', 'Custom')}
              </DetailField>
              <DetailField label={t('scans.capabilities.detail.color', 'Color')}>
                <span className="inline-flex items-center gap-2 capitalize">
                  {/* The capability's own accent colour, chosen by its author. */}
                  <span
                    aria-hidden
                    className={`size-3 rounded-full ${TAG_SWATCH_CLASS[capabilitySwatch(capability.color)]}`}
                  />
                  {capabilitySwatch(capability.color)}
                </span>
              </DetailField>
              <DetailField label={t('scans.capabilities.detail.icon', 'Icon')}>
                <span className="inline-flex items-center gap-2">
                  <DynamicIcon name={capability.icon} className="h-4 w-4" />
                  {capability.icon}
                </span>
              </DetailField>
              <DetailField label={t('scans.capabilities.detail.id', 'ID')} full>
                <DetailCopyId
                  id={capability.id}
                  label={t('scans.capabilities.detail.idLabel', 'Capability ID')}
                />
              </DetailField>
            </DetailFieldGrid>
          </DetailSection>
        </DetailSections>
      </div>
    </DetailSheet>
  )
})
