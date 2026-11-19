'use client'

import { capabilitySwatch } from '@/lib/capability-colors'
import { TAG_SWATCH_CLASS } from '@/lib/tag-colors'
import type * as React from 'react'
import { useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Pencil, Trash2, Globe, Sparkles, Wrench, Bot, Eye } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { DynamicIcon } from '@/components/dynamic-icon'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  type DataTableSearch,
} from '@/features/shared'

import type { Capability, CapabilityUsageStatsBatchResponse } from '@/lib/api/capability-types'
import { useToolAvailability } from '@/lib/api/tool-hooks'
import type { ToolAvailabilityItem } from '@/lib/api/tool-types'
import { toolStatusLabel, availabilityByName, isRunnable } from '@/features/tools/lib/availability'
import { useTranslation } from '@/context/i18n-provider'

interface CapabilityTableProps {
  capabilities: Capability[]
  usageStats?: CapabilityUsageStatsBatchResponse
  onEdit?: (capability: Capability) => void
  onDelete?: (capability: Capability) => void
  onViewDetails?: (capability: Capability) => void
  readOnly?: boolean
  /** Passed through to the DataTable toolbar (search, filters, view toggle). */
  search?: DataTableSearch
  toolbarStart?: React.ReactNode
  toolbarEnd?: React.ReactNode
}

// Usage badges (tool + sensor counts) with tooltips — unchanged from the original.
function UsageCell({
  stats,
  availability,
}: {
  stats?: CapabilityUsageStatsBatchResponse[string]
  /** Tool availability by name (the Tools page's source); null while unknown. */
  availability: Map<string, ToolAvailabilityItem> | null
}) {
  const { t } = useTranslation()
  if (!stats) return <span className="text-muted-foreground">-</span>
  const ready = availability
    ? (stats.tool_names ?? []).filter((n) => {
        const a = availability.get(n)
        return !!a && isRunnable(a)
      }).length
    : null
  return (
    <div className="flex items-center gap-2">
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant={stats.tool_count > 0 ? 'default' : 'outline'}
            className="gap-1 cursor-help"
          >
            <Wrench className="h-3 w-3" />
            {stats.tool_count}
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          <p className="font-medium">
            {stats.tool_count === 0
              ? t('scans.capabilities.usage.noTools', 'No tools using this capability')
              : stats.tool_count === 1
                ? t('scans.capabilities.usage.toolsOne', '{count} tool', {
                    count: stats.tool_count,
                  })
                : t('scans.capabilities.usage.toolsMany', '{count} tools', {
                    count: stats.tool_count,
                  })}
            {ready != null &&
              stats.tool_count > 0 &&
              t('scans.capabilities.usage.ready', ', {ready} ready on your sensors', { ready })}
          </p>
          {stats.tool_names && stats.tool_names.length > 0 && (
            <ul className="mt-1 list-disc ps-4 text-xs text-muted-foreground">
              {stats.tool_names.slice(0, 5).map((name) => {
                const a = availability?.get(name)
                return (
                  <li key={name}>
                    {name}
                    {a && ` (${toolStatusLabel(a.status, t).toLowerCase()})`}
                  </li>
                )
              })}
              {stats.tool_names.length > 5 && (
                <li>
                  {t('scans.capabilities.usage.more', '+{count} more', {
                    count: stats.tool_names.length - 5,
                  })}
                </li>
              )}
            </ul>
          )}
        </TooltipContent>
      </Tooltip>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant={stats.sensor_count > 0 ? 'default' : 'outline'}
            className="gap-1 cursor-help"
          >
            <Bot className="h-3 w-3" />
            {stats.sensor_count}
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          <p className="font-medium">
            {stats.sensor_count === 0
              ? t('scans.capabilities.usage.noSensors', 'No sensors with this capability')
              : stats.sensor_count === 1
                ? t('scans.capabilities.usage.sensorsOne', '{count} sensor', {
                    count: stats.sensor_count,
                  })
                : t('scans.capabilities.usage.sensorsMany', '{count} sensors', {
                    count: stats.sensor_count,
                  })}
          </p>
          {stats.sensor_names && stats.sensor_names.length > 0 && (
            <ul className="mt-1 list-disc ps-4 text-xs text-muted-foreground">
              {stats.sensor_names.slice(0, 5).map((name) => (
                <li key={name}>{name}</li>
              ))}
              {stats.sensor_names.length > 5 && (
                <li>
                  {t('scans.capabilities.usage.more', '+{count} more', {
                    count: stats.sensor_names.length - 5,
                  })}
                </li>
              )}
            </ul>
          )}
        </TooltipContent>
      </Tooltip>
    </div>
  )
}

export function CapabilityTable({
  capabilities,
  usageStats,
  onEdit,
  onDelete,
  onViewDetails,
  readOnly = false,
  search,
  toolbarStart,
  toolbarEnd,
}: CapabilityTableProps) {
  const { t } = useTranslation()
  const showActions = Boolean(onViewDetails || (!readOnly && (onEdit || onDelete)))
  // Which of a capability's tools a scan can run now (api tool-availability.md).
  const { data: availData } = useToolAvailability()
  const availability = useMemo(
    () => (availData ? availabilityByName(availData.items) : null),
    [availData]
  )

  const columns = useMemo<ColumnDef<Capability>[]>(() => {
    const cols: ColumnDef<Capability>[] = [
      {
        accessorKey: 'display_name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.capabilities.col.name', 'Name')} />
        ),
        cell: ({ row }) => {
          const c = row.original
          return (
            <div className="flex items-center gap-2">
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground`}
              >
                <DynamicIcon name={c.icon} className="h-4 w-4" />
              </div>
              <span className="font-medium">{c.display_name}</span>
              <span
                aria-hidden
                className={`size-2 shrink-0 rounded-full ${TAG_SWATCH_CLASS[capabilitySwatch(c.color)]}`}
              />
            </div>
          )
        },
      },
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.capabilities.col.code', 'Code')} />
        ),
        cell: ({ row }) => (
          <code className="text-xs text-muted-foreground">{row.original.name}</code>
        ),
      },
      {
        accessorKey: 'category',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scans.capabilities.col.category', 'Category')}
          />
        ),
        cell: ({ row }) =>
          row.original.category ? (
            <Badge variant="outline" className="capitalize">
              {row.original.category}
            </Badge>
          ) : null,
      },
      {
        accessorKey: 'is_builtin',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.capabilities.col.type', 'Type')} />
        ),
        cell: ({ row }) => (
          <Badge variant="secondary" className="gap-1">
            {row.original.is_builtin ? (
              <>
                <Globe className="h-3 w-3" />
                {t('scans.capabilities.type.platform', 'Platform')}
              </>
            ) : (
              <>
                <Sparkles className="h-3 w-3" />
                {t('scans.capabilities.type.custom', 'Custom')}
              </>
            )}
          </Badge>
        ),
      },
      {
        id: 'usage',
        header: t('scans.capabilities.col.usage', 'Usage'),
        enableSorting: false,
        cell: ({ row }) => (
          <UsageCell stats={usageStats?.[row.original.id]} availability={availability} />
        ),
      },
      {
        accessorKey: 'description',
        header: t('scans.capabilities.col.description', 'Description'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="line-clamp-1 max-w-[300px] text-sm text-muted-foreground">
            {row.original.description || '-'}
          </span>
        ),
      },
    ]

    if (showActions) {
      cols.push({
        id: 'actions',
        header: '',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const c = row.original
          const actions = [
            ...(onViewDetails
              ? [
                  {
                    label: t('scans.capabilities.action.viewDetails', 'View details'),
                    icon: Eye,
                    onClick: () => onViewDetails(c),
                  },
                ]
              : []),
            ...(!readOnly && onEdit
              ? [
                  {
                    label: t('scans.capabilities.action.edit', 'Edit'),
                    icon: Pencil,
                    onClick: () => onEdit(c),
                  },
                ]
              : []),
            ...(!readOnly && onDelete
              ? [
                  {
                    label: t('scans.capabilities.action.delete', 'Delete'),
                    icon: Trash2,
                    onClick: () => onDelete(c),
                    destructive: true,
                    separatorBefore: true,
                  },
                ]
              : []),
          ]
          return <DataTableRowActions title={c.display_name} actions={actions} />
        },
      })
    }

    return cols
  }, [usageStats, availability, showActions, onViewDetails, onEdit, onDelete, readOnly, t])

  // Parent (capabilities-section) owns search + tab/category filters, so the
  // table's own search is disabled; DataTable adds sortable headers + pagination.
  return (
    <DataTable
      columns={columns}
      data={capabilities}
      showSearch={false}
      search={search}
      toolbarStart={toolbarStart}
      toolbarEnd={toolbarEnd}
      emptyMessage={t('scans.capabilities.table.emptyTitle', 'No capabilities')}
      emptyDescription={t(
        'scans.capabilities.table.emptyDesc',
        'No capabilities match the current filters.'
      )}
    />
  )
}
