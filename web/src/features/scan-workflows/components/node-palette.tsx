'use client'

import { Tag } from '@/components/ui/tag'
import { HealthStatus } from '@/components/ui/health-status'
import { TAG_SWATCH_CLASS, tagColorForName } from '@/lib/tag-colors'
import { useState, useMemo } from 'react'
import {
  Radar,
  Search,
  Globe,
  Server,
  Shield,
  FileSearch,
  Bug,
  Network,
  Fingerprint,
  ChevronDown,
  ChevronRight,
  SearchIcon,
  Loader2,
  AlertCircle,
  Wrench,
  Code,
  Container,
  Key,
  FileCode,
  Scan,
  Cloud,
  User,
} from 'lucide-react'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { useToolAvailability, useToolsWithConfig } from '@/lib/api/tool-hooks'
import {
  TOOL_STATUS_META,
  availabilityByName,
  toolUnavailableReason,
} from '@/features/tools/lib/availability'
import { useCapabilityMetadata } from '@/lib/api'
import type { ToolWithConfig } from '@/lib/api/tool-types'
import { safeImageSrc } from '@/lib/safe-href'
import { ToolTrustBadge } from '@/features/tools/components/tool-availability'
import Image from 'next/image'

// Map Lucide icon names from database to actual components
const ICON_MAP: Record<string, React.ElementType> = {
  code: Code,
  package: FileCode,
  globe: Globe,
  key: Key,
  server: Server,
  box: Container,
  search: Search,
  eye: Search,
  bug: Bug,
  radar: Radar,
  scan: Scan,
  fingerprint: Fingerprint,
  network: Network,
  'file-search': FileSearch,
  'file-code': FileCode,
  shield: Shield,
  wrench: Wrench,
}

// Get icon from category (dynamic from database) or fallback
function getIconForTool(tool: ToolWithConfig['tool']): React.ElementType {
  // Use category icon from database if available
  if (tool.category?.icon) {
    const icon = ICON_MAP[tool.category.icon]
    if (icon) return icon
  }
  // Fallback to generic scanner
  return Radar
}

// Group tools by their category (from embedded category info)
function groupToolsByCategory(tools: ToolWithConfig[]): Map<string, ToolWithConfig[]> {
  const groups = new Map<string, ToolWithConfig[]>()

  // Define category display order (slug -> display name fallback)
  const categoryOrder = ['sast', 'sca', 'dast', 'secrets', 'iac', 'container', 'recon', 'osint']

  // First pass: collect all unique categories and their display names
  const categoryDisplayNames = new Map<string, string>()
  tools.forEach((toolWithConfig) => {
    const cat = toolWithConfig.tool.category
    if (cat) {
      categoryDisplayNames.set(cat.name, cat.display_name)
    }
  })

  // Initialize groups in order
  categoryOrder.forEach((slug) => {
    const displayName = categoryDisplayNames.get(slug)
    if (displayName) {
      groups.set(displayName, [])
    }
  })
  groups.set('Other', [])

  // Group tools by category
  tools.forEach((toolWithConfig) => {
    const cat = toolWithConfig.tool.category
    if (cat && categoryDisplayNames.has(cat.name)) {
      const displayName = categoryDisplayNames.get(cat.name)!
      if (!groups.has(displayName)) {
        groups.set(displayName, [])
      }
      groups.get(displayName)!.push(toolWithConfig)
    } else {
      groups.get('Other')!.push(toolWithConfig)
    }
  })

  // Remove empty groups
  groups.forEach((tools, key) => {
    if (tools.length === 0) {
      groups.delete(key)
    }
  })

  return groups
}

interface NodePaletteProps {
  onDragStart?: (event: React.DragEvent, nodeType: string, capabilities?: string[]) => void
  position?: 'left' | 'right'
}

export function NodePalette({ onDragStart, position = 'right' }: NodePaletteProps) {
  const { t } = useTranslation()
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set())

  // Fetch capability metadata for display names
  const { getDisplayName: getCapabilityDisplayName } = useCapabilityMetadata()

  // Fetch tools from API
  const { data: toolsData, isLoading, error } = useToolsWithConfig()

  // Why a tool cannot run now (the same source as the Tools page).
  const { data: availData } = useToolAvailability()
  const availability = useMemo(() => availabilityByName(availData?.items), [availData])

  // Filter only enabled tools
  const enabledTools = useMemo(() => {
    if (!toolsData?.items) return []
    return toolsData.items.filter((t) => t.is_enabled && t.tool.is_active)
  }, [toolsData])

  // Group tools by category
  const groupedTools = useMemo(() => {
    return groupToolsByCategory(enabledTools)
  }, [enabledTools])

  // Categories start collapsed by default - no initialization needed
  // User can expand categories as needed

  const handleDragStart = (event: React.DragEvent, toolWithConfig: ToolWithConfig) => {
    const tool = toolWithConfig.tool
    // Store tool data for drop handler
    event.dataTransfer.setData('application/reactflow', 'scanner')
    event.dataTransfer.setData('application/node-label', tool.display_name || tool.name)
    event.dataTransfer.setData(
      'application/node-capabilities',
      JSON.stringify(tool.capabilities || [])
    )
    event.dataTransfer.setData('application/tool-name', tool.name)
    event.dataTransfer.setData('application/tool-id', tool.id)
    // Pass category color for node styling
    if (tool.category?.color) {
      event.dataTransfer.setData('application/category-color', tool.category.color)
    }
    event.dataTransfer.effectAllowed = 'move'
    onDragStart?.(event, 'scanner', tool.capabilities)
  }

  const toggleCategory = (categoryName: string) => {
    setExpandedCategories((prev) => {
      const newSet = new Set(prev)
      if (newSet.has(categoryName)) {
        newSet.delete(categoryName)
      } else {
        newSet.add(categoryName)
      }
      return newSet
    })
  }

  // Filter tools by search
  const filteredGroups = useMemo(() => {
    if (!searchQuery) return groupedTools

    const filtered = new Map<string, ToolWithConfig[]>()

    groupedTools.forEach((tools, category) => {
      const matchingTools = tools.filter((t) => {
        const tool = t.tool
        const searchLower = searchQuery.toLowerCase()
        return (
          tool.name.toLowerCase().includes(searchLower) ||
          tool.display_name.toLowerCase().includes(searchLower) ||
          tool.description?.toLowerCase().includes(searchLower) ||
          tool.capabilities?.some((c) => c.toLowerCase().includes(searchLower))
        )
      })

      if (matchingTools.length > 0) {
        filtered.set(category, matchingTools)
      }
    })

    return filtered
  }, [groupedTools, searchQuery])

  // Loading state
  if (isLoading) {
    return (
      <div
        className={cn(
          'w-60 bg-muted/30 h-full flex flex-col items-center justify-center',
          position === 'left' ? 'border-r' : 'border-l'
        )}
      >
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        <p className="text-xs text-muted-foreground mt-2">{t('workflowStages.palette.loading')}</p>
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div
        className={cn(
          'w-60 bg-muted/30 h-full flex flex-col items-center justify-center p-4',
          position === 'left' ? 'border-r' : 'border-l'
        )}
      >
        <AlertCircle className="h-6 w-6 text-destructive" />
        <p className="text-xs text-muted-foreground mt-2 text-center">
          {t('workflowStages.palette.loadFailed')}
        </p>
      </div>
    )
  }

  return (
    <div
      className={cn(
        'w-60 bg-muted/30 h-full flex flex-col',
        position === 'left' ? 'border-r' : 'border-l'
      )}
    >
      {/* Header */}
      <div className="p-3 border-b">
        <h4 className="text-sm font-semibold mb-2">{t('workflowStages.palette.title')}</h4>
        <div className="relative">
          <SearchIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder={t('workflowStages.palette.search')}
            aria-label={t('workflowStages.palette.search')}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-8 ps-8 text-xs"
          />
        </div>
        <p className="text-[10px] text-muted-foreground mt-2">
          {t('workflowStages.palette.available', '{count} tools available', {
            count: enabledTools.length,
          })}
        </p>
      </div>

      {/* Categories */}
      <div className="flex-1 overflow-y-auto p-2 space-y-1">
        {filteredGroups.size === 0 ? (
          <div className="text-center py-8">
            <Wrench className="h-8 w-8 text-muted-foreground/50 mx-auto" />
            <p className="text-xs text-muted-foreground mt-2">
              {searchQuery
                ? t('workflowStages.palette.noMatch')
                : t('workflowStages.palette.noneEnabled')}
            </p>
          </div>
        ) : (
          Array.from(filteredGroups.entries()).map(([category, tools]) => {
            const isExpanded = expandedCategories.has(category)

            return (
              <div key={category}>
                {/* Category Header */}
                <button
                  onClick={() => toggleCategory(category)}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-muted/50 text-sm font-medium"
                >
                  {isExpanded ? (
                    <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                  )}
                  <span className="truncate">{category}</span>
                  <span className="ms-auto text-xs text-muted-foreground">{tools.length}</span>
                </button>

                {/* Tools in Category */}
                {isExpanded && (
                  <div className="ms-2 mt-1 space-y-1">
                    {tools.map((toolWithConfig) => {
                      const tool = toolWithConfig.tool
                      const Icon = getIconForTool(tool)
                      const swatch = tagColorForName(tool.category?.color)
                      const isAvailable = toolWithConfig.is_available === true
                      const avail = availability.get(tool.name)
                      const unavailableReason =
                        toolUnavailableReason(avail) ?? t('workflowStages.palette.noOnlineSensor')
                      const logoSrc = safeImageSrc(tool.logo_url)

                      return (
                        <div
                          key={tool.id}
                          draggable={isAvailable}
                          onDragStart={(e) => isAvailable && handleDragStart(e, toolWithConfig)}
                          className={cn(
                            'flex items-center gap-2.5 px-2 py-2 rounded-lg border border-transparent bg-card transition-all',
                            isAvailable
                              ? 'hover:border-border hover:shadow-sm cursor-grab active:cursor-grabbing'
                              : 'opacity-50 cursor-not-allowed'
                          )}
                          title={
                            isAvailable
                              ? tool.description
                              : `${tool.display_name || tool.name}: ${unavailableReason}`
                          }
                        >
                          {logoSrc ? (
                            // unoptimized: the logo URL is tenant/remote data; it must not
                            // be fetched through the Next image optimizer (no remotePatterns).
                            <Image
                              src={logoSrc}
                              alt={tool.display_name}
                              width={32}
                              height={32}
                              unoptimized
                              className={cn(
                                'h-8 w-8 rounded-lg object-contain bg-white p-0.5',
                                !isAvailable && 'grayscale'
                              )}
                            />
                          ) : (
                            <div
                              className={cn(
                                'relative h-8 w-8 rounded-lg flex items-center justify-center flex-shrink-0 bg-muted'
                              )}
                            >
                              <Icon className="h-4 w-4 text-foreground" />
                              {isAvailable && (
                                <span
                                  aria-hidden
                                  className={cn(
                                    'absolute -right-0.5 -top-0.5 size-2 rounded-full ring-2 ring-card',
                                    TAG_SWATCH_CLASS[swatch]
                                  )}
                                />
                              )}
                            </div>
                          )}
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1">
                              <span
                                className={cn(
                                  'text-xs font-medium leading-tight truncate',
                                  !isAvailable && 'text-muted-foreground'
                                )}
                              >
                                {tool.display_name || tool.name}
                              </span>
                              {/* Show badge for platform vs custom tools */}
                              {tool.is_platform_tool ? (
                                <Tag
                                  variant="plain"
                                  icon={Cloud}
                                  label={t('workflowStages.palette.platform')}
                                />
                              ) : (
                                <Tag
                                  variant="plain"
                                  icon={User}
                                  label={t('workflowStages.palette.custom')}
                                />
                              )}
                              {avail && (
                                <ToolTrustBadge item={avail} className="text-[9px] px-1 py-0" />
                              )}
                              {/* Show badge for unavailable tools */}
                              {!isAvailable && (
                                <HealthStatus
                                  state="down"
                                  label={
                                    avail
                                      ? TOOL_STATUS_META[avail.status].label
                                      : t('workflowStages.palette.noSensor')
                                  }
                                />
                              )}
                            </div>
                            {tool.capabilities && tool.capabilities.length > 0 && (
                              <span className="text-[10px] text-muted-foreground leading-tight">
                                {tool.capabilities
                                  .slice(0, 2)
                                  .map((c) => getCapabilityDisplayName(c))
                                  .join(', ')}
                                {tool.capabilities.length > 2 && '...'}
                              </span>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>

      {/* Footer Tips */}
      <div className="p-3 border-t bg-muted/20">
        <p className="text-[10px] text-muted-foreground leading-relaxed">
          {t('workflowStages.palette.hint')}
        </p>
      </div>
    </div>
  )
}
