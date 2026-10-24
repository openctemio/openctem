/**
 * Capability Badge Component
 *
 * A reusable badge component for displaying capability names with:
 * - Dynamic colors from capability metadata
 * - Optional icons from capability metadata
 * - Consistent styling across the application
 *
 * @example
 * ```tsx
 * // Basic usage
 * <CapabilityBadge name="sast" />
 *
 * // With icon
 * <CapabilityBadge name="sast" showIcon />
 *
 * // Compact size for nodes/cards
 * <CapabilityBadge name="sast" size="sm" />
 *
 * // Multiple capabilities
 * {capabilities.map(cap => (
 *   <CapabilityBadge key={cap} name={cap} showIcon />
 * ))}
 * ```
 */

'use client'

import { memo } from 'react'
import { Tag } from '@/components/ui/tag'
import { Counter } from '@/components/ui/counter'
import { capabilitySwatch } from '@/lib/capability-colors'
import { useTranslation } from '@/context/i18n-provider'
import { useCapabilityMetadata } from '@/lib/api'
import { cn } from '@/lib/utils'
import {
  Code,
  Package,
  Globe,
  Key,
  Server,
  Box,
  AlertTriangle,
  Search,
  Layers,
  Wifi,
  Radio,
  FileText,
  Cloud,
  Container,
  Zap,
  type LucideIcon,
} from 'lucide-react'

// Map icon names to Lucide components
const ICON_MAP: Record<string, LucideIcon> = {
  code: Code,
  package: Package,
  globe: Globe,
  'globe-2': Globe,
  key: Key,
  server: Server,
  box: Box,
  'alert-triangle': AlertTriangle,
  search: Search,
  layers: Layers,
  wifi: Wifi,
  radio: Radio,
  'file-text': FileText,
  'file-code': Code,
  cloud: Cloud,
  container: Container,
  zap: Zap,
  // Add spider alias (not in lucide, use search as fallback)
  spider: Search,
}

interface CapabilityBadgeProps {
  /** The capability name (e.g., 'sast', 'sca', 'secrets') */
  name: string
  /** Whether to show the capability icon */
  showIcon?: boolean
  /** Size variant */
  size?: 'sm' | 'default'
  /** Additional class names */
  className?: string
}

function CapabilityBadgeComponent({
  name,
  showIcon = false,
  size = 'default',
  className,
}: CapabilityBadgeProps) {
  const { getDisplayName, getColor, getIcon } = useCapabilityMetadata()

  const displayName = getDisplayName(name)
  const color = getColor(name)
  const iconName = getIcon(name)

  const IconComponent = showIcon ? ICON_MAP[iconName] || Zap : undefined

  return (
    <Tag
      label={displayName}
      icon={IconComponent}
      swatch={capabilitySwatch(color)}
      className={cn(size === 'sm' && 'h-5', className)}
    />
  )
}

/**
 * Memoized capability badge component
 * Use this for rendering lists of capabilities to avoid unnecessary re-renders
 */
export const CapabilityBadge = memo(CapabilityBadgeComponent)

/**
 * Render a list of capability badges
 * Convenience wrapper for rendering multiple capabilities
 */
export function CapabilityBadgeList({
  capabilities,
  showIcon = false,
  size = 'default',
  className,
  maxVisible,
}: {
  capabilities: string[]
  showIcon?: boolean
  size?: 'sm' | 'default'
  className?: string
  /** Maximum number of visible badges (rest will show as "+N more") */
  maxVisible?: number
}) {
  const { t } = useTranslation()
  if (!capabilities || capabilities.length === 0) {
    return null
  }

  const visibleCaps = maxVisible ? capabilities.slice(0, maxVisible) : capabilities
  const hiddenCount = maxVisible ? Math.max(0, capabilities.length - maxVisible) : 0

  return (
    <div className={cn('flex flex-wrap gap-1', className)}>
      {visibleCaps.map((cap) => (
        <CapabilityBadge key={cap} name={cap} showIcon={showIcon} size={size} />
      ))}
      {hiddenCount > 0 && (
        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
          <Counter value={hiddenCount} />
          <span className="sr-only">
            {t('labels.more', '+{count} more', { count: hiddenCount })}
          </span>
        </span>
      )}
    </div>
  )
}
