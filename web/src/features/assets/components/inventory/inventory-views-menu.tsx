'use client'

/**
 * The inventory's Views menu: the shared saved views (page `assets`: the
 * person's own, those shared with a group or the organization) and, above
 * them, the built-in starter views. A starter view is a small filter patch
 * that turns on and off; its check mark reads straight from the current
 * filters (preset.isActive), so it stays in sync when the same dimension is set
 * from the panel, the query text, a metric or the URL. The trigger names the
 * open saved view, or the starter views that are on.
 */

import {
  CalendarClock,
  CalendarX,
  Clock,
  Flame,
  Gem,
  Globe,
  Network,
  UserX,
  CircleSlash,
  Radar,
  ShieldOff,
  Sparkles,
} from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import {
  SavedViewsMenu,
  type BuiltInView,
} from '@/features/saved-views/components/saved-views-menu'
import type { SavedView } from '@/features/saved-views/api/use-saved-views'
import type { QuickPreset } from '../../lib/inventory-facets'
import type { InventoryFilters } from '../../lib/inventory-url'

const PRESET_ICONS: Record<string, React.ElementType> = {
  'crown-jewels': Gem,
  'internet-facing': Globe,
  'critical-with-findings': Flame,
  unowned: UserX,
  'control-planes': Network,
  stale: Clock,
  expired: CalendarX,
  'expiring-30d': CalendarClock,
  'not-in-scope': ShieldOff,
  discovered: Radar,
  'out-of-scope': CircleSlash,
  'new-since-visit': Sparkles,
}

interface InventoryViewsMenuProps {
  filters: InventoryFilters
  /** The starter views: the common ones, the open tab's and those of this list only. */
  presets: QuickPreset[]
  onToggle: (preset: QuickPreset) => void
  /** The filter to save as a view: the list's own params, or its checked document. */
  resolveFilter: () => Promise<{ query?: string; filter?: Record<string, unknown> }>
  /** The open saved view differs from what is stored. */
  modified: boolean
  onDiscard: () => void
  onSelect: (view: SavedView | null) => void
}

export function InventoryViewsMenu({
  filters,
  presets,
  onToggle,
  resolveFilter,
  modified,
  onDiscard,
  onSelect,
}: InventoryViewsMenuProps) {
  const { t } = useTranslation()
  const builtIn: BuiltInView[] = presets.map((p) => ({
    id: p.id,
    label: p.labelKey ? t(p.labelKey, p.label) : p.label,
    icon: PRESET_ICONS[p.id],
    checked: p.isActive(filters),
    onToggle: () => onToggle(p),
  }))
  return (
    <SavedViewsMenu
      page="assets"
      resolveFilter={resolveFilter}
      builtIn={builtIn}
      builtInLabel={t('assets.views.starter', 'Starter views')}
      activeId={filters.view}
      modified={modified}
      onDiscard={onDiscard}
      onSelect={onSelect}
    />
  )
}
