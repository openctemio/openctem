'use client'

/**
 * The inventory's filter row (research/242 D6): what the default list hides,
 * every active filter as a removable chip, then Add filter, with the result
 * count at the end. Add filter lists the same facets as the phone filter
 * sheet (one registry, `lib/inventory-facets`), searchable and grouped; picking
 * one opens that facet's own editor, which applies as you tick, so a chip
 * appears behind the popover at once.
 */

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { ArrowLeft, Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { ResponsivePopover } from '@/features/shared/components/responsive-popover'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import type { AssetStatsData } from '../../hooks/use-assets'
import type { FacetGroup } from '../../lib/inventory-facets'
import type { InventoryChip } from '../../lib/inventory-chips'
import type { InventoryFilters } from '../../lib/inventory-url'
import {
  AttributeFacetSection,
  BoolFacetSection,
  MultiFacetSection,
  SignalsSection,
  type AttributeFacet,
} from './inventory-facet-panel'
import { InventoryTagsFacet } from './inventory-tags-facet'
import { InventoryTechnologiesFacet } from './inventory-technologies-facet'

/** One entry of the Add filter list. */
interface FilterField {
  id: string
  group: string
  label: string
  editor: (props: EditorProps) => ReactNode
}

interface EditorProps {
  filters: InventoryFilters
  stats: AssetStatsData
  onChange: (next: InventoryFilters) => void
}

/** The Add filter list, in the panel's order: type attributes, facets, signals, technology, tags. */
function useFilterFields(
  groups: FacetGroup[],
  attributeFacets: AttributeFacet[],
  tagTypes: string[] | undefined
): FilterField[] {
  const { t } = useTranslation()
  return useMemo(() => {
    const fields: FilterField[] = attributeFacets.map((f) => ({
      id: `attr:${f.attribute.key}`,
      group: t('assets.filters.group.attributes', 'Attributes'),
      label: f.label,
      editor: (p) => <AttributeFacetSection facet={f} defaultOpen {...p} />,
    }))
    for (const g of groups) {
      for (const facet of g.facets) {
        fields.push({
          id: facet.filterKey,
          group: g.label,
          label: facet.label,
          editor: (p) =>
            facet.kind === 'multi' ? (
              <MultiFacetSection facet={facet} defaultOpen {...p} />
            ) : (
              <BoolFacetSection facet={facet} defaultOpen {...p} />
            ),
        })
      }
    }
    const signals = t('assets.facetPanel.signals', 'Signals')
    fields.push(
      {
        id: 'signals',
        group: signals,
        label: t('assets.filters.signals', 'Crown jewels, findings, coverage, freshness'),
        editor: (p) => <SignalsSection filters={p.filters} onChange={p.onChange} defaultOpen />,
      },
      {
        id: 'technologies',
        group: signals,
        label: t('assets.technologies.title', 'Technologies'),
        editor: (p) => (
          <InventoryTechnologiesFacet filters={p.filters} onChange={p.onChange} defaultOpen />
        ),
      },
      {
        id: 'tags',
        group: signals,
        label: t('assets.tagFilter.title', 'Tags'),
        editor: (p) => (
          <InventoryTagsFacet
            filters={p.filters}
            onChange={p.onChange}
            types={tagTypes}
            defaultOpen
          />
        ),
      }
    )
    return fields
  }, [groups, attributeFacets, tagTypes, t])
}

/** Opens on `f` anywhere outside a text field or an open menu or dialog. */
function useShortcut(onOpen: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'f' || e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return
      const el = e.target as HTMLElement | null
      if (
        el?.closest?.(
          'input, textarea, select, [contenteditable="true"], [role="combobox"], [role="listbox"], [role="menu"], [role="dialog"], [role="alertdialog"]'
        )
      )
        return
      e.preventDefault()
      onOpen()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onOpen])
}

function AddFilter({
  fields,
  filters,
  stats,
  onChange,
  className,
  onOpenChange,
}: {
  fields: FilterField[]
  className?: string
  onOpenChange?: (open: boolean) => void
} & EditorProps) {
  const { t } = useTranslation()
  const [open, setOpenState] = useState(false)
  const [picked, setPicked] = useState<FilterField | null>(null)
  const setOpen = (next: boolean) => {
    setOpenState(next)
    if (!next) setPicked(null)
    onOpenChange?.(next)
  }
  const openPicker = useMemo(
    () => () => {
      setOpenState(true)
      onOpenChange?.(true)
    },
    [onOpenChange]
  )
  useShortcut(openPicker)

  const byGroup = useMemo(() => {
    const m = new Map<string, FilterField[]>()
    for (const f of fields) m.set(f.group, [...(m.get(f.group) ?? []), f])
    return [...m.entries()]
  }, [fields])

  return (
    <ResponsivePopover
      open={open}
      onOpenChange={setOpen}
      title={t('assets.filters.add', 'Add filter')}
      className="w-80"
      trigger={
        <Button
          variant="outline"
          size="sm"
          className={`h-7 gap-1 rounded-full border-dashed px-2.5 text-xs ${className ?? ''}`}
          aria-keyshortcuts="f"
        >
          <Plus className="size-3" aria-hidden />
          {t('assets.filters.add', 'Add filter')}
          <kbd
            className="ms-1 rounded border px-1 font-sans text-xs text-muted-foreground"
            aria-hidden
          >
            f
          </kbd>
        </Button>
      }
    >
      {picked ? (
        <div className="flex max-h-[min(28rem,70svh)] flex-col">
          <div className="flex items-center gap-1 border-b px-1 py-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-xs"
              onClick={() => setPicked(null)}
            >
              <ArrowLeft className="size-3.5" aria-hidden />
              {t('assets.filters.back', 'All filters')}
            </Button>
            <Button size="sm" className="ms-auto h-7 px-3 text-xs" onClick={() => setOpen(false)}>
              {t('assets.filters.done', 'Done')}
            </Button>
          </div>
          <div className="min-h-0 overflow-y-auto px-3 pb-2">
            {picked.editor({ filters, stats, onChange })}
          </div>
        </div>
      ) : (
        <Command>
          <CommandInput placeholder={t('assets.filters.search', 'Search filters…')} />
          <CommandList>
            <CommandEmpty>{t('assets.filters.noField', 'No matching filter')}</CommandEmpty>
            {byGroup.map(([group, items]) => (
              <CommandGroup key={group} heading={group}>
                {items.map((f) => (
                  <CommandItem
                    key={f.id}
                    value={`${f.label} ${f.id}`}
                    onSelect={() => setPicked(f)}
                  >
                    {f.label}
                  </CommandItem>
                ))}
              </CommandGroup>
            ))}
          </CommandList>
        </Command>
      )}
    </ResponsivePopover>
  )
}

/** One active filter: its sentence and a remove button. */
export function InventoryFilterChip({
  chip,
  onRemove,
}: {
  chip: InventoryChip
  onRemove: () => void
}) {
  const { t } = useTranslation()
  // Values can be discovered data (tags, technologies, attribute values): text only.
  const text = toDisplayText(chip.text, 120)
  return (
    <span
      data-testid="inventory-filter-chip"
      className="inline-flex max-w-full items-center gap-1 rounded-full border bg-muted/50 py-0.5 ps-2.5 pe-1 text-xs"
    >
      <span dir="auto" className="min-w-0 truncate [unicode-bidi:isolate]" title={text}>
        {text}
      </span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={t('assets.filters.remove', 'Remove filter {filter}', { filter: text })}
        className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <X className="size-3" aria-hidden />
      </button>
    </span>
  )
}

export function InventoryFilterBar({
  chips,
  locked,
  groups,
  attributeFacets = [],
  tagTypes,
  filters,
  stats,
  onChange,
  onClearAll,
  onPickerOpenChange,
  resultLabel,
}: {
  chips: InventoryChip[]
  /** What the default list hides (a `LockedChip`), first in the row. */
  locked?: ReactNode
  groups: FacetGroup[]
  attributeFacets?: AttributeFacet[]
  tagTypes?: string[]
  onClearAll: () => void
  /** Told when Add filter opens or closes (to load what its editors label). */
  onPickerOpenChange?: (open: boolean) => void
  /** "361 assets", at the end of the row. */
  resultLabel?: string
} & EditorProps) {
  const { t } = useTranslation()
  const fields = useFilterFields(groups, attributeFacets, tagTypes)
  return (
    <FilterChipsRow
      data-testid="inventory-filter-bar"
      leading={locked}
      chips={chips.map((c) => (
        <InventoryFilterChip key={c.key} chip={c} onRemove={() => onChange(c.clear(filters))} />
      ))}
      trailing={
        <>
          <AddFilter
            className="hidden lg:inline-flex"
            fields={fields}
            filters={filters}
            stats={stats}
            onChange={onChange}
            onOpenChange={onPickerOpenChange}
          />
          {chips.length > 1 && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-muted-foreground"
              onClick={onClearAll}
            >
              {t('assets.filters.clearAll', 'Clear filters')}
            </Button>
          )}
        </>
      }
      end={resultLabel ? <span role="status">{resultLabel}</span> : undefined}
    />
  )
}
