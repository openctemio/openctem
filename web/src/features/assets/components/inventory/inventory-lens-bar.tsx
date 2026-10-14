'use client'

/**
 * The registry's lenses as a row of filter pills above the inventory (All,
 * External surface, Applications, ... and Other), each with its asset count
 * from the data-scoped stats; a lens with no asset is hidden. With a lens
 * picked, a second row lists its asset types with counts, multi-select, kept
 * in the URL as `?types=`. This bar is the one place to filter by type.
 *
 * Both rows are toolbars: Tab enters a row, arrow keys, Home and End move
 * along it, and every pill states whether it is on (aria-pressed).
 */

import * as React from 'react'
import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'
import { ASSET_LENSES, type AssetLens } from '@/features/asset-types/registry.generated'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { LensCounts } from '../../lib/inventory-lenses'

/** The lens bar's selection: a lens, or "Other" (types outside every lens). */
export interface LensSelection {
  lens: AssetLens | undefined
  types: string[] | undefined
}

interface InventoryLensBarProps {
  registry: AssetTypeRegistry | undefined
  value: AssetLens | undefined
  /** The `?types=` selection. */
  types?: string[]
  /** Scoped counts; undefined while loading (every lens shows, without a number). */
  counts?: LensCounts
  /** All assets the caller can see (the "All" pill's number). */
  total?: number
  onChange: (next: LensSelection) => void
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

/** Arrow keys, Home and End move focus along a toolbar's buttons. */
function onToolbarKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
  const keys = ['ArrowRight', 'ArrowLeft', 'Home', 'End']
  if (!keys.includes(e.key)) return
  const buttons = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>('button'))
  const i = buttons.indexOf(document.activeElement as HTMLButtonElement)
  if (i < 0) return
  e.preventDefault()
  const rtl = getComputedStyle(e.currentTarget).direction === 'rtl'
  const n = buttons.length
  let next: number
  if (e.key === 'Home') next = 0
  else if (e.key === 'End') next = n - 1
  else {
    const d = (e.key === 'ArrowRight' ? 1 : -1) * (rtl ? -1 : 1)
    next = (i + d + n) % n
  }
  buttons[next]?.focus()
  buttons[next]?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
}

function Pill({
  active,
  label,
  count,
  onClick,
  tabIndex,
  small,
}: {
  active: boolean
  label: string
  count?: number
  onClick: () => void
  tabIndex: number
  small?: boolean
}) {
  return (
    <Button
      type="button"
      size="sm"
      variant={active ? 'secondary' : 'ghost'}
      aria-pressed={active}
      tabIndex={tabIndex}
      className={cn(
        'h-7 shrink-0 rounded-full px-3 text-xs',
        small && 'h-6 px-2.5',
        active && 'font-semibold'
      )}
      onClick={onClick}
    >
      {label}
      {count !== undefined && (
        <span
          className={cn('ms-1.5 tabular-nums text-muted-foreground', active && 'text-foreground')}
        >
          {count.toLocaleString()}
        </span>
      )}
    </Button>
  )
}

export function InventoryLensBar({
  registry,
  value,
  types,
  counts,
  total,
  onChange,
  className,
}: InventoryLensBarProps) {
  const { t } = useTranslation()
  const selectedTypes = types ?? []
  const otherSelected =
    !value &&
    !!counts &&
    counts.otherTypes.length > 0 &&
    selectedTypes.length > 0 &&
    selectedTypes.every((s) => counts.otherTypes.includes(s))

  const lenses = inventoryLenses(registry).filter(
    (l) => !counts || (counts.byLens[l.id] ?? 0) > 0 || l.id === value
  )
  const pills: {
    key: string
    label: string
    count?: number
    active: boolean
    onClick: () => void
  }[] = [
    {
      key: 'all',
      label: t('assets.lens.all', 'All'),
      count: total,
      active: !value && !otherSelected && selectedTypes.length === 0,
      onClick: () => onChange({ lens: undefined, types: undefined }),
    },
    ...lenses.map((l) => ({
      key: l.id,
      label: t(`assets.lens.${l.id}`, l.label),
      count: counts ? (counts.byLens[l.id] ?? 0) : undefined,
      active: l.id === value,
      // A lens replaces the type picks: a type outside it would match nothing.
      onClick: () => onChange({ lens: l.id, types: undefined }),
    })),
    ...(counts && counts.other > 0
      ? [
          {
            key: 'other',
            label: t('assets.lens.other', 'Other'),
            count: counts.other,
            active: otherSelected,
            onClick: () => onChange({ lens: undefined, types: [...counts.otherTypes] }),
          },
        ]
      : []),
  ]
  const activePill = Math.max(
    0,
    pills.findIndex((p) => p.active)
  )

  const chips = value && counts ? (counts.chips[value] ?? []) : []
  // A selected type the counts do not list (none in scope) stays removable.
  const chipList = [
    ...chips,
    ...selectedTypes
      .filter((s) => !chips.some((c) => c.type === s))
      .map((s) => ({ type: s, label: s, count: 0 })),
  ]
  const toggleType = (type: string) => {
    const next = selectedTypes.includes(type)
      ? selectedTypes.filter((s) => s !== type)
      : [...selectedTypes, type]
    onChange({ lens: value, types: next.length > 0 ? next : undefined })
  }

  return (
    <div className={cn('space-y-2', className)} data-slot="inventory-lens-bar">
      <div
        role="toolbar"
        aria-label={t('assets.lens.label', 'Asset lens')}
        onKeyDown={onToolbarKeyDown}
        className="-mx-1 flex items-center gap-1.5 overflow-x-auto px-1 pb-1 [scrollbar-width:thin] sm:flex-wrap sm:overflow-visible sm:pb-0"
      >
        {pills.map((p, i) => (
          <Pill
            key={p.key}
            active={p.active}
            label={p.label}
            count={p.count}
            onClick={p.onClick}
            tabIndex={i === activePill ? 0 : -1}
          />
        ))}
      </div>
      {value && chipList.length > 1 && (
        <div
          role="toolbar"
          aria-label={t('assets.lens.typesLabel', 'Asset types in {lens}', {
            lens: t(`assets.lens.${value}`, lenses.find((l) => l.id === value)?.label ?? value),
          })}
          onKeyDown={onToolbarKeyDown}
          className="-mx-1 flex items-center gap-1 overflow-x-auto px-1 pb-1 [scrollbar-width:thin] sm:flex-wrap sm:overflow-visible sm:pb-0"
        >
          {chipList.map((c, i) => (
            <Pill
              key={c.type}
              small
              active={selectedTypes.includes(c.type)}
              label={t(`assets.typeLabel.${c.type}`, c.label)}
              count={c.count}
              onClick={() => toggleType(c.type)}
              tabIndex={i === 0 ? 0 : -1}
            />
          ))}
        </div>
      )}
    </div>
  )
}
