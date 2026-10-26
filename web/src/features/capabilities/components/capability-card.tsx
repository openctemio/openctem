'use client'

import { capabilitySwatch } from '@/lib/capability-colors'
import { TAG_SWATCH_CLASS } from '@/lib/tag-colors'
import { memo } from 'react'
import { Pencil, Trash2, Globe, Sparkles, Wrench, Bot, Eye } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { DynamicIcon } from '@/components/dynamic-icon'
import { DataTableRowActions } from '@/features/shared'

import type { Capability, CapabilityUsageStats } from '@/lib/api/capability-types'

interface CapabilityCardProps {
  capability: Capability
  usageStats?: CapabilityUsageStats
  onEdit?: (capability: Capability) => void
  onDelete?: (capability: Capability) => void
  onViewDetails?: (capability: Capability) => void
  readOnly?: boolean
}

export const CapabilityCard = memo(function CapabilityCard({
  capability,
  usageStats,
  onEdit,
  onDelete,
  onViewDetails,
  readOnly = false,
}: CapabilityCardProps) {
  const showActions = !readOnly && (onEdit || onDelete)

  return (
    <Card className="group relative transition-all hover:shadow-md">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground`}
            >
              <DynamicIcon name={capability.icon} className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <CardTitle className="flex items-center gap-1.5 text-base leading-tight">
                <span
                  aria-hidden
                  className={`size-2 shrink-0 rounded-full ${TAG_SWATCH_CLASS[capabilitySwatch(capability.color)]}`}
                />
                {capability.display_name}
              </CardTitle>
              <code className="text-xs text-muted-foreground">{capability.name}</code>
            </div>
          </div>
          {(showActions || onViewDetails) && (
            <DataTableRowActions
              actions={[
                ...(onViewDetails
                  ? [
                      {
                        label: 'View Details',
                        icon: Eye,
                        onClick: () => onViewDetails(capability),
                      },
                    ]
                  : []),
                ...(onEdit
                  ? [
                      {
                        label: 'Edit',
                        icon: Pencil,
                        onClick: () => onEdit(capability),
                        separatorBefore: !!onViewDetails,
                      },
                    ]
                  : []),
                ...(onDelete
                  ? [
                      {
                        label: 'Delete',
                        icon: Trash2,
                        onClick: () => onDelete(capability),
                        destructive: true,
                        separatorBefore: !!onViewDetails && !onEdit,
                      },
                    ]
                  : []),
              ]}
            />
          )}
        </div>
      </CardHeader>
      <CardContent>
        {capability.description && (
          <CardDescription className="line-clamp-2 text-sm">
            {capability.description}
          </CardDescription>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {capability.category && (
            <Badge variant="outline" className="capitalize">
              {capability.category}
            </Badge>
          )}
          <Badge variant="secondary" className="gap-1">
            {capability.is_builtin ? (
              <>
                <Globe className="h-3 w-3" />
                Platform
              </>
            ) : (
              <>
                <Sparkles className="h-3 w-3" />
                Custom
              </>
            )}
          </Badge>
          {/* Usage Stats Badges */}
          {usageStats && (
            <>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant={usageStats.tool_count > 0 ? 'default' : 'outline'}
                    className="gap-1 cursor-help"
                  >
                    <Wrench className="h-3 w-3" />
                    {usageStats.tool_count}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="font-medium">
                    {usageStats.tool_count === 0
                      ? 'No tools using this capability'
                      : `${usageStats.tool_count} tool${usageStats.tool_count > 1 ? 's' : ''} using this capability`}
                  </p>
                  {usageStats.tool_names && usageStats.tool_names.length > 0 && (
                    <ul className="mt-1 list-disc ps-4 text-xs text-muted-foreground">
                      {usageStats.tool_names.slice(0, 5).map((name) => (
                        <li key={name}>{name}</li>
                      ))}
                      {usageStats.tool_names.length > 5 && (
                        <li>+{usageStats.tool_names.length - 5} more</li>
                      )}
                    </ul>
                  )}
                </TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant={usageStats.sensor_count > 0 ? 'default' : 'outline'}
                    className="gap-1 cursor-help"
                  >
                    <Bot className="h-3 w-3" />
                    {usageStats.sensor_count}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="font-medium">
                    {usageStats.sensor_count === 0
                      ? 'No sensors with this capability'
                      : `${usageStats.sensor_count} sensor${usageStats.sensor_count > 1 ? 's' : ''} with this capability`}
                  </p>
                  {usageStats.sensor_names && usageStats.sensor_names.length > 0 && (
                    <ul className="mt-1 list-disc ps-4 text-xs text-muted-foreground">
                      {usageStats.sensor_names.slice(0, 5).map((name) => (
                        <li key={name}>{name}</li>
                      ))}
                      {usageStats.sensor_names.length > 5 && (
                        <li>+{usageStats.sensor_names.length - 5} more</li>
                      )}
                    </ul>
                  )}
                </TooltipContent>
              </Tooltip>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  )
})
