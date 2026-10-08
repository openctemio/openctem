'use client'

/**
 * The registry's lenses as a row of filter pills above the inventory: All,
 * External surface, Applications, ... One lens at a time, kept in the URL as
 * `?lens=`. The list is the registry's, so a new lens appears here with no
 * web change.
 */

import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'
import { ASSET_LENSES, type AssetLens } from '@/features/asset-types/registry.generated'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

interface InventoryLensBarProps {
  registry: AssetTypeRegistry | undefined
  value: AssetLens | undefined
  onChange: (lens: AssetLens | undefined) => void
  className?: string
}

/** The registry's lenses in order (the generated list until it has loaded). */
export function inventoryLenses(
  registry: AssetTypeRegistry | undefined
): { id: AssetLens; label: string }[] {
  const served = (registry?.lenses ?? [])
    .filter((l): l is typeof l & { id: AssetLens } => ASSET_LENSES.some((g) => g.id === l.id))
    .map((l) => ({ id: l.id, label: l.label ?? l.id }))
  return served.length > 0 ? served : ASSET_LENSES.map((l) => ({ id: l.id, label: l.label }))
}

export function InventoryLensBar({ registry, value, onChange, className }: InventoryLensBarProps) {
  const items: { id: AssetLens | undefined; label: string }[] = [
    { id: undefined, label: 'All' },
    ...inventoryLenses(registry),
  ]
  return (
    <div
      role="group"
      aria-label="Asset lens"
      className={cn('flex flex-wrap items-center gap-1.5', className)}
      data-slot="inventory-lens-bar"
    >
      {items.map((item) => {
        const active = item.id === value
        return (
          <Button
            key={item.id ?? 'all'}
            type="button"
            size="sm"
            variant={active ? 'secondary' : 'ghost'}
            aria-pressed={active}
            className={cn('h-7 rounded-full px-3 text-xs', active && 'font-semibold')}
            onClick={() => onChange(item.id)}
          >
            {item.label}
          </Button>
        )
      })}
    </div>
  )
}
