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
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { AddFilterButton, ShowFilterPanelButton } from '@/features/shared/components/filter-button'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
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
import { AdvancedChip } from '@/features/query/components/query-mode'
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
      // In Query mode the filter tokens are inert: the text owns the filter.
      if (document.querySelector('[data-slot="list-toolbar-tokens"][inert]')) return
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

/**
 * The inventory's "Add filter", on the toolbar row after the search (from
 * `lg` up; below it the Filters sheet holds every facet).
 */
export function InventoryAddFilter({
  groups,
  attributeFacets = [],
  tagTypes,
  filters,
  stats,
  onChange,
  onOpenChange,
  onOpenPanel,
}: {
  groups: FacetGroup[]
  attributeFacets?: AttributeFacet[]
  tagTypes?: string[]
  /** Told when Add filter opens or closes (to load what its editors label). */
  onOpenChange?: (open: boolean) => void
  /** Open the facet panel (the picker's last row). */
  onOpenPanel?: () => void
} & EditorProps) {
  const fields = useFilterFields(groups, attributeFacets, tagTypes)
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
      trigger={<AddFilterButton />}
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
          {onOpenPanel && (
            <ShowFilterPanelButton
              onClick={() => {
                setOpen(false)
                onOpenPanel()
              }}
            />
          )}
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
    <RemovableFilterChip
      data-testid="inventory-filter-chip"
      text={text}
      onRemove={onRemove}
      removeLabel={t('assets.filters.remove', 'Remove filter {filter}', { filter: text })}
    />
  )
}

export function InventoryFilterBar({
  chips,
  locked,
  filters,
  onChange,
  onClearAll,
  queryActive,
  onOpenQuery,
}: {
  chips: InventoryChip[]
  /** What the default list hides (a `LockedChip`), first in the row. */
  locked?: ReactNode
  onClearAll: () => void
  /**
   * The search field is in Query mode (lib/inventory-text): the text owns the
   * filter, so the chips, Add filter and Clear step aside.
   */
  queryActive?: boolean
  /** Open the search field's Query mode (the Advanced chip's text). */
  onOpenQuery?: () => void
} & Pick<EditorProps, 'filters' | 'onChange'>) {
  const advancedChip = filters.advanced ? (
    <AdvancedChip
      key="advanced"
      text={filters.advanced}
      onOpen={() => onOpenQuery?.()}
      onRemove={() => onChange({ ...filters, advanced: undefined, page: 1 })}
    />
  ) : null
  if (queryActive) {
    return locked ? (
      <FilterChipsRow data-testid="inventory-filter-bar" leading={locked} chips={[]} />
    ) : null
  }
  return (
    <FilterChipsRow
      data-testid="inventory-filter-bar"
      leading={locked}
      chips={[
        ...(advancedChip ? [advancedChip] : []),
        ...chips.map((c) => (
          <InventoryFilterChip key={c.key} chip={c} onRemove={() => onChange(c.clear(filters))} />
        )),
      ]}
      onClearAll={chips.length + (advancedChip ? 1 : 0) > 1 ? onClearAll : undefined}
    />
  )
}
