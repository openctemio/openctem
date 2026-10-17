'use client'

/**
 * The Technologies section of the inventory filter panel (RFC-112).
 *
 * - Categories (web servers, CDN, hosting, ...) are a fixed list: ticking
 *   one keeps assets with a technology in it.
 * - Technologies are `GET /assets/technologies`: the ones on the assets the
 *   viewer may list (tenant and data scope applied by the API), most used
 *   first, with a search box that asks the API. Ticking one keeps assets
 *   using it; several are an "any of".
 * Selected values stay visible (and removable) even when the list does not
 * contain them. No counts in the options: they would ignore the other active
 * filters (the panel's rule).
 */

import { useState } from 'react'
import { Search } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { FacetGroupLabel, FacetOption, FacetSection } from '@/features/shared'
import { useDebounce } from '@/hooks/use-debounce'
import { useTechnologyFacets } from '../../hooks/use-asset-technologies'
import type { InventoryFilters } from '../../lib/inventory-url'
import { TECHNOLOGY_CATEGORIES, useCategoryLabel } from '../technologies/technologies-by-category'

/** Technologies shown before "Show more" (selected ones are always shown). */
const COLLAPSED_COUNT = 8

function toggle(list: string[] | undefined, value: string, on: boolean): string[] | undefined {
  const next = new Set(list ?? [])
  if (on) next.add(value)
  else next.delete(value)
  return next.size > 0 ? [...next] : undefined
}

export function InventoryTechnologiesFacet({
  filters,
  onChange,
}: {
  filters: InventoryFilters
  onChange: (next: InventoryFilters) => void
}) {
  const { t } = useTranslation()
  const categoryLabel = useCategoryLabel()
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState(false)
  const [open, setOpen] = useState(false)
  const q = useDebounce(query.trim(), 250)
  const selectedTech = filters.technologies ?? []
  const selectedCats = filters.technologyCategories ?? []
  // Ask only once the section is opened or something is selected.
  const { facets } = useTechnologyFacets(q || undefined, open || selectedTech.length > 0)

  const names = new Map(facets.map((f) => [f.key, f.name]))
  const listed = facets.map((f) => f.key)
  const keys = [...selectedTech.filter((k) => !listed.includes(k)), ...listed]
  const shown = expanded ? keys : keys.slice(0, Math.max(COLLAPSED_COUNT, selectedTech.length))
  const patch = (p: Partial<InventoryFilters>) => onChange({ ...filters, ...p, page: 1 })

  return (
    <FacetSection
      title={t('assets.technologies.title', 'Technologies')}
      selectedCount={selectedTech.length + selectedCats.length}
      defaultOpen={selectedTech.length + selectedCats.length > 0}
      onOpenChange={setOpen}
    >
      <FacetGroupLabel>{t('assets.technologies.filter.category', 'Category')}</FacetGroupLabel>
      {TECHNOLOGY_CATEGORIES.map((c) => (
        <FacetOption
          key={c}
          label={categoryLabel(c)}
          checked={selectedCats.includes(c)}
          onCheckedChange={(on) =>
            patch({ technologyCategories: toggle(filters.technologyCategories, c, on) })
          }
        />
      ))}
      <FacetGroupLabel>{t('assets.technologies.filter.technology', 'Technology')}</FacetGroupLabel>
      <div className="relative px-1 pb-1">
        <Search className="pointer-events-none absolute top-2.5 left-3 h-3.5 w-3.5 text-muted-foreground" />
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('assets.technologies.filter.search', 'Search technologies')}
          aria-label={t('assets.technologies.filter.search', 'Search technologies')}
          maxLength={128}
          className="h-8 pl-7 text-sm"
        />
      </div>
      {shown.map((k) => (
        <FacetOption
          key={k}
          label={names.get(k) ?? k}
          checked={selectedTech.includes(k)}
          onCheckedChange={(on) => patch({ technologies: toggle(filters.technologies, k, on) })}
        />
      ))}
      {keys.length === 0 && (
        <p className="px-2 py-1 text-xs text-muted-foreground">
          {t('assets.technologies.filter.none', 'No technologies detected yet')}
        </p>
      )}
      {!expanded && keys.length > shown.length && (
        <button
          type="button"
          className="px-2 py-1 text-xs font-medium text-muted-foreground hover:text-foreground"
          onClick={() => setExpanded(true)}
        >
          {t('assets.technologies.filter.more', 'Show {count} more', {
            count: keys.length - shown.length,
          })}
        </button>
      )}
    </FacetSection>
  )
}
