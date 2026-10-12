'use client'

import type * as React from 'react'
import { useMemo, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import Image from 'next/image'
import { ArrowUpCircle, ExternalLink, Eye, Github, Settings, Trash2 } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  type RowAction,
} from '@/features/shared'
import type { Tool, ToolAvailabilityItem } from '@/lib/api/tool-types'
import type { ToolCategory } from '@/lib/api/tool-category-types'
import { getCategoryNameById, getCategoryDisplayNameById } from '@/lib/api/tool-category-hooks'
import { formatRelative } from '@/lib/format-date'
import { safeImageSrc } from '@/lib/safe-href'
import { sanitizeExternalUrl } from '@/lib/utils'

import { TOOL_AVAILABILITY_STATUSES, toolDisplayName, versionsLabel } from '../lib/availability'
import { ToolCategoryIcon } from './tool-category-icon'
import { ToolSensorsCell, ToolStatusBadge, ToolTrustBadge } from './tool-availability'

interface ToolTableProps {
  items: ToolAvailabilityItem[]
  categories?: ToolCategory[] // For looking up category name from category_id
  onViewTool: (item: ToolAvailabilityItem) => void
  onEditTool?: (tool: Tool) => void
  onDeleteTool?: (tool: Tool) => void
  /** Switch the tool on or off for the organization; omitted without permission. */
  onToggleEnabled?: (item: ToolAvailabilityItem, enabled: boolean) => void
  /** Passed through to the DataTable toolbar (search, filters). */
  toolbarStart?: React.ReactNode
  toolbarEnd?: React.ReactNode
  emptyMessage?: string
}

// SECURITY: tool github_url / docs_url are tenant-authored and the API's URL
// validator accepts opaque schemes such as `javascript:`. Route through the
// shared sanitizer (same guard every other window.open site uses) so a stored
// `javascript:`/`data:` URL cannot execute when another user clicks the action.
const openExternal = (url: string) =>
  window.open(sanitizeExternalUrl(url), '_blank', 'noopener,noreferrer')

const STATUS_ORDER = new Map(TOOL_AVAILABILITY_STATUSES.map((s, i) => [s, i]))

export function ToolTable({
  items,
  categories,
  onViewTool,
  onEditTool,
  onDeleteTool,
  onToggleEnabled,
  toolbarStart,
  toolbarEnd,
  emptyMessage = 'No tools match these filters',
}: ToolTableProps) {
  const categoryName = useCallback(
    (item: ToolAvailabilityItem) => getCategoryNameById(categories, item.tool?.category_id),
    [categories]
  )
  const categoryDisplayName = useCallback(
    (item: ToolAvailabilityItem) =>
      item.tool ? getCategoryDisplayNameById(categories, item.tool.category_id) : '',
    [categories]
  )

  const columns = useMemo<ColumnDef<ToolAvailabilityItem>[]>(
    () => [
      {
        id: 'name',
        accessorFn: (i) => `${toolDisplayName(i)} ${i.name} ${i.tool?.description ?? ''}`,
        sortingFn: (a, b) => toolDisplayName(a.original).localeCompare(toolDisplayName(b.original)),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Tool" />,
        cell: ({ row }) => {
          const item = row.original
          const logoSrc = safeImageSrc(item.tool?.logo_url)
          return (
            <div className="flex min-w-0 items-center gap-3">
              {logoSrc ? (
                // unoptimized: the logo URL is tenant/remote data; it must not be
                // fetched through the Next image optimizer (no remotePatterns).
                <Image
                  src={logoSrc}
                  alt=""
                  width={28}
                  height={28}
                  unoptimized
                  className="h-7 w-7 shrink-0 rounded-md object-contain"
                />
              ) : (
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-muted">
                  <ToolCategoryIcon
                    category={categoryName(item)}
                    className="h-4 w-4 text-muted-foreground"
                  />
                </div>
              )}
              <div className="min-w-0">
                <p className="flex items-center gap-1.5 truncate font-medium">
                  <span className="truncate">{toolDisplayName(item)}</span>
                  {item.tool && !item.tool.is_builtin && (
                    <Badge variant="outline" className="text-[10px] font-normal">
                      Custom
                    </Badge>
                  )}
                  {!item.in_catalog && (
                    <Badge variant="outline" className="text-[10px] font-normal">
                      Not in catalog
                    </Badge>
                  )}
                </p>
                <p className="truncate font-mono text-xs text-muted-foreground">{item.name}</p>
              </div>
            </div>
          )
        },
      },
      {
        id: 'category',
        accessorFn: (i) => categoryDisplayName(i),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Category" />,
        cell: ({ row }) =>
          row.original.tool ? (
            <Badge variant="outline" className="gap-1">
              <ToolCategoryIcon category={categoryName(row.original)} className="h-3 w-3" />
              {categoryDisplayName(row.original)}
            </Badge>
          ) : (
            <span className="text-xs text-muted-foreground">–</span>
          ),
      },
      {
        id: 'status',
        accessorFn: (i) => STATUS_ORDER.get(i.status) ?? 99,
        header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
        cell: ({ row }) => (
          <span className="inline-flex flex-wrap items-center gap-1">
            <ToolStatusBadge item={row.original} />
            <ToolTrustBadge item={row.original} />
          </span>
        ),
      },
      {
        id: 'sensors',
        accessorFn: (i) => i.sensors_online * 1000 + i.sensors_total,
        header: ({ column }) => <DataTableColumnHeader column={column} title="Sensors" />,
        cell: ({ row }) => <ToolSensorsCell item={row.original} />,
      },
      {
        id: 'versions',
        accessorFn: (i) => versionsLabel(i),
        enableSorting: false,
        header: 'Version(s)',
        cell: ({ row }) => {
          const item = row.original
          const label = versionsLabel(item)
          return (
            <div className="flex items-center gap-2">
              <span className="text-xs tabular-nums">{label || '–'}</span>
              {item.update_available && item.latest_version && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Badge variant="secondary" className="gap-1 tabular-nums">
                      <ArrowUpCircle className="h-3 w-3" />
                      {item.latest_version}
                    </Badge>
                  </TooltipTrigger>
                  <TooltipContent>
                    A sensor runs an older version than {item.latest_version}, the newest known
                  </TooltipContent>
                </Tooltip>
              )}
            </div>
          )
        },
      },
      {
        id: 'last_reported',
        accessorFn: (i) => i.last_reported_at ?? '',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Last reported" />,
        cell: ({ row }) => (
          <span
            className="text-xs text-muted-foreground"
            title={row.original.last_reported_at ?? undefined}
          >
            {formatRelative(row.original.last_reported_at, '–')}
          </span>
        ),
      },
      {
        id: 'enabled',
        accessorFn: (i) => (i.enabled ? 1 : 0),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Enabled" />,
        cell: ({ row }) => {
          const item = row.original
          // A tool outside the catalog, or one the platform switched off,
          // has no organization switch.
          const switchable = !!onToggleEnabled && !!item.tool && item.tool.is_active
          return (
            <span onClick={(e) => e.stopPropagation()} className="inline-flex">
              <Switch
                checked={item.enabled}
                disabled={!switchable}
                aria-label={`${item.enabled ? 'Disable' : 'Enable'} ${toolDisplayName(item)}`}
                onCheckedChange={(on) => onToggleEnabled?.(item, on)}
              />
            </span>
          )
        },
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const item = row.original
          const tool = item.tool
          const actions: RowAction[] = [
            { label: 'View details', icon: Eye, onClick: () => onViewTool(item) },
          ]
          if (tool && !tool.is_builtin && onEditTool) {
            actions.push({ label: 'Edit', icon: Settings, onClick: () => onEditTool(tool) })
          }
          if (tool?.github_url) {
            const url = tool.github_url
            actions.push({ label: 'GitHub', icon: Github, onClick: () => openExternal(url) })
          }
          if (tool?.docs_url) {
            const url = tool.docs_url
            actions.push({
              label: 'Documentation',
              icon: ExternalLink,
              onClick: () => openExternal(url),
            })
          }
          if (tool && !tool.is_builtin && onDeleteTool) {
            actions.push({
              label: 'Delete',
              icon: Trash2,
              onClick: () => onDeleteTool(tool),
              destructive: true,
              separatorBefore: true,
            })
          }
          return <DataTableRowActions actions={actions} />
        },
      },
    ],
    [onViewTool, onEditTool, onDeleteTool, onToggleEnabled, categoryName, categoryDisplayName]
  )

  return (
    <DataTable
      columns={columns}
      data={items}
      getRowId={(i) => i.name}
      showSearch={false}
      onRowClick={onViewTool}
      toolbarStart={toolbarStart}
      toolbarEnd={toolbarEnd}
      emptyMessage={emptyMessage}
    />
  )
}
