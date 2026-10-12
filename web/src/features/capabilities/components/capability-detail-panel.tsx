'use client'

import { memo } from 'react'
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

// Get color class from color name
function getColorClass(color: string) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-500/10 text-blue-500',
    purple: 'bg-purple-500/10 text-purple-500',
    green: 'bg-green-500/10 text-green-500',
    red: 'bg-red-500/10 text-red-500',
    orange: 'bg-orange-500/10 text-orange-500',
    cyan: 'bg-cyan-500/10 text-cyan-500',
    yellow: 'bg-yellow-500/10 text-yellow-500',
    lime: 'bg-lime-500/10 text-lime-500',
    teal: 'bg-teal-500/10 text-teal-500',
    indigo: 'bg-indigo-500/10 text-indigo-500',
    fuchsia: 'bg-fuchsia-500/10 text-fuchsia-500',
    amber: 'bg-amber-500/10 text-amber-500',
    violet: 'bg-violet-500/10 text-violet-500',
    sky: 'bg-sky-500/10 text-sky-500',
    slate: 'bg-slate-500/10 text-slate-500',
    gray: 'bg-gray-500/10 text-gray-500',
    emerald: 'bg-emerald-500/10 text-emerald-500',
  }
  return colorMap[color] || 'bg-primary/10 text-primary'
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
  // Fetch usage stats with full details (includes names)
  const { data: usageStats, isLoading } = useCapabilityUsageStats(open ? capability?.id : null)

  // Use fetched data, fall back to initial stats for instant counts display
  const stats = usageStats || initialStats
  const hasNames = usageStats?.tool_names || usageStats?.sensor_names
  const isLoadingNames = isLoading && !hasNames

  if (!capability) return null

  const colorClass = getColorClass(capability.color)

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
                {capability.is_builtin ? 'Platform' : 'Custom'}
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
        <DetailStatGrid aria-label="Usage">
          <DetailStat label="Tools" value={stats?.tool_count ?? 0} />
          <DetailStat label="Sensors" value={stats?.sensor_count ?? 0} />
        </DetailStatGrid>

        <DetailSections>
          {capability.description && (
            <DetailSection title="Description">
              <p className="text-sm text-muted-foreground">{capability.description}</p>
            </DetailSection>
          )}

          <DetailSection
            title="Tools"
            icon={Wrench}
            count={stats?.tool_count || undefined}
            actions={
              stats && stats.tool_count > 0 ? (
                <Link
                  href="/settings/scanning/tools"
                  className="flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  View all
                  <ExternalLink className="h-3 w-3" />
                </Link>
              ) : undefined
            }
          >
            <NameList
              names={usageStats?.tool_names}
              icon={Wrench}
              empty="No tools are using this capability."
              loading={isLoadingNames}
            />
          </DetailSection>

          <DetailSection
            title="Sensors"
            icon={Bot}
            count={stats?.sensor_count || undefined}
            actions={
              stats && stats.sensor_count > 0 ? (
                <Link
                  href="/sensors"
                  className="flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  View all
                  <ExternalLink className="h-3 w-3" />
                </Link>
              ) : undefined
            }
          >
            <NameList
              names={usageStats?.sensor_names}
              icon={Bot}
              empty="No sensors have this capability assigned."
              loading={isLoadingNames}
            />
          </DetailSection>

          <DetailSection title="Details">
            <DetailFieldGrid>
              <DetailField label="Code name">
                <span className="font-mono text-xs break-all">{capability.name}</span>
              </DetailField>
              <DetailField label="Category">
                <span className="capitalize">{capability.category || '-'}</span>
              </DetailField>
              <DetailField label="Type">
                {capability.is_builtin ? 'Platform' : 'Custom'}
              </DetailField>
              <DetailField label="Color">
                <span className="inline-flex items-center gap-2 capitalize">
                  {/* The capability's own accent colour, chosen by its author. */}
                  <span className={`h-3 w-3 rounded-full ${colorClass.split(' ')[0]}`} />
                  {capability.color}
                </span>
              </DetailField>
              <DetailField label="Icon">
                <span className="inline-flex items-center gap-2">
                  <DynamicIcon name={capability.icon} className="h-4 w-4" />
                  {capability.icon}
                </span>
              </DetailField>
              <DetailField label="ID" full>
                <DetailCopyId id={capability.id} label="Capability ID" />
              </DetailField>
            </DetailFieldGrid>
          </DetailSection>
        </DetailSections>
      </div>
    </DetailSheet>
  )
})
