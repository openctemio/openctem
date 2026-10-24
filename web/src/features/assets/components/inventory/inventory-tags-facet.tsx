'use client'

/**
 * The Tags section of the inventory filter panel.
 *
 * - The vocabulary is `GET /assets/tags`: the tags of the assets the viewer
 *   may list (tenant and data scope applied by the API), most used first.
 *   A search box asks the API (substring), so tags beyond the first page can
 *   be found.
 * - Each tag can be included (the checkbox) or excluded (the minus button);
 *   with two or more included tags, Any / All sets the match mode.
 * - System tags (set by the platform from bug-bounty program links) are a
 *   group of their own: they filter the same way but are read-only on assets.
 * - No per-tag counts: they would ignore the other active filters (the
 *   panel's rule).
 * Tags selected in the URL stay visible (and removable) even when the list
 * does not contain them.
 */

import { useState } from 'react'
import { Lock, MinusCircle, Search } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { FacetGroupLabel, FacetOption, FacetSection } from '@/features/shared'
import { useDebounce } from '@/hooks/use-debounce'
import { cn } from '@/lib/utils'
import { useAssetTags } from '../../hooks/use-asset-tags'
import {
  toggleExcludedTag,
  toggleIncludedTag,
  type InventoryFilters,
} from '../../lib/inventory-url'

/** Tags shown before "Show N more" (selected tags are always shown). */
const COLLAPSED_COUNT = 6
/** How many tags (and system tags) the panel asks for. */
const TAG_LIST_LIMIT = 100

interface InventoryTagsFacetProps {
  filters: InventoryFilters
  onChange: (next: InventoryFilters) => void
  /** Typed mode: only the tags of assets of these types. */
  types?: string[]
  /** Unfold it (the Add filter editor). */
  defaultOpen?: boolean
}

export function InventoryTagsFacet({
  filters,
  onChange,
  types,
  defaultOpen = false,
}: InventoryTagsFacetProps) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState(false)
  const q = useDebounce(query.trim(), 250)
  const { tags, systemTags, isLoading } = useAssetTags(undefined, true, types, {
    q: q || undefined,
    includeSystem: true,
    limit: TAG_LIST_LIMIT,
  })

  const included = filters.tags ?? []
  const excluded = filters.excludeTags ?? []
  const selected = new Set([...included, ...excluded])
  const systemSet = new Set(systemTags)

  // Selected tags the list does not hold (another page, or from a shared
  // link) are listed with the user tags so they can be removed.
  const userTags = tags.filter((tag) => !systemSet.has(tag))
  const missing = [...selected].filter((tag) => !userTags.includes(tag) && !systemSet.has(tag))
  const allUser = q
    ? [...userTags, ...missing.filter((tag) => tag.toLowerCase().includes(q.toLowerCase()))]
    : [...userTags, ...missing]
  const shownUser =
    q || expanded ? allUser : allUser.filter((tag, i) => i < COLLAPSED_COUNT || selected.has(tag))
  const hiddenCount = allUser.length - shownUser.length

  const row = (tag: string, system: boolean) => (
    <TagRow
      key={`${system ? 's' : 'u'}:${tag}`}
      tag={tag}
      system={system}
      included={included.includes(tag)}
      excluded={excluded.includes(tag)}
      onInclude={() => onChange(toggleIncludedTag(filters, tag))}
      onExclude={() => onChange(toggleExcludedTag(filters, tag))}
    />
  )

  const empty = allUser.length === 0 && systemTags.length === 0

  return (
    <FacetSection
      title={t('assets.tagFilter.title', 'Tags')}
      selectedCount={included.length + excluded.length}
      defaultOpen={defaultOpen}
    >
      {included.length > 1 && (
        <MatchMode
          mode={filters.tagsMode === 'all' ? 'all' : 'any'}
          onChange={(mode) =>
            onChange({ ...filters, tagsMode: mode === 'all' ? 'all' : undefined, page: 1 })
          }
        />
      )}
      <div className="relative mb-1.5">
        <Search className="pointer-events-none absolute start-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('assets.tagFilter.search', 'Search tags…')}
          aria-label={t('assets.tagFilter.search', 'Search tags…')}
          maxLength={50}
          className="h-8 ps-7 text-xs"
        />
      </div>
      {empty ? (
        <p className="py-1 text-xs text-muted-foreground">
          {isLoading
            ? t('assets.tagFilter.loading', 'Loading tags…')
            : q
              ? t('assets.tagFilter.noMatches', 'No matching tags.')
              : t('assets.tagFilter.none', 'No tags in this workspace yet.')}
        </p>
      ) : (
        <>
          {shownUser.map((tag) => row(tag, false))}
          {!q && (hiddenCount > 0 || expanded) && (
            <button
              type="button"
              onClick={() => setExpanded((e) => !e)}
              className="px-1.5 pt-1 text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
            >
              {expanded
                ? t('assets.tagFilter.showFewer', 'Show fewer')
                : t('assets.tagFilter.showMore', 'Show {count} more', { count: hiddenCount })}
            </button>
          )}
          {systemTags.length > 0 && (
            <>
              <FacetGroupLabel>{t('assets.tagFilter.systemGroup', 'System tags')}</FacetGroupLabel>
              {systemTags.map((tag) => row(tag, true))}
            </>
          )}
        </>
      )}
    </FacetSection>
  )
}

function MatchMode({
  mode,
  onChange,
}: {
  mode: 'any' | 'all'
  onChange: (mode: 'any' | 'all') => void
}) {
  const { t } = useTranslation()
  const options: { value: 'any' | 'all'; label: string; hint: string }[] = [
    {
      value: 'any',
      label: t('assets.tagFilter.matchAny', 'Any'),
      hint: t('assets.tagFilter.matchAnyHint', 'Assets with at least one of the selected tags'),
    },
    {
      value: 'all',
      label: t('assets.tagFilter.matchAll', 'All'),
      hint: t('assets.tagFilter.matchAllHint', 'Assets with every selected tag'),
    },
  ]
  return (
    <div className="mb-1.5 flex items-center gap-2 px-1.5">
      <span className="text-xs text-muted-foreground">{t('assets.tagFilter.match', 'Match')}</span>
      <div
        role="radiogroup"
        aria-label={t('assets.tagFilter.match', 'Match')}
        className="inline-flex rounded-md border p-0.5"
      >
        {options.map((o) => (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={mode === o.value}
            title={o.hint}
            onClick={() => onChange(o.value)}
            className={cn(
              'rounded px-2 py-0.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              mode === o.value
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  )
}

function TagRow({
  tag,
  system,
  included,
  excluded,
  onInclude,
  onExclude,
}: {
  tag: string
  system: boolean
  included: boolean
  excluded: boolean
  onInclude: () => void
  onExclude: () => void
}) {
  const { t } = useTranslation()
  return (
    <div className="flex items-center gap-1" data-testid={`tag-facet-row-${tag}`}>
      <div className="min-w-0 flex-1">
        <FacetOption
          label={
            <span title={tag} className={cn(excluded && 'text-muted-foreground line-through')}>
              {tag}
            </span>
          }
          adornment={
            system ? (
              <Lock
                className="h-3 w-3 shrink-0 text-muted-foreground"
                aria-label={t('assets.tagFilter.systemReadOnly', 'Set by the platform, read-only')}
              />
            ) : undefined
          }
          checked={included}
          onCheckedChange={onInclude}
        />
      </div>
      <button
        type="button"
        onClick={onExclude}
        aria-pressed={excluded}
        aria-label={t('assets.tagFilter.exclude', 'Exclude {tag}', { tag })}
        title={t('assets.tagFilter.excludeHint', 'Exclude assets with this tag')}
        className={cn(
          'shrink-0 rounded p-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          excluded ? 'text-destructive' : 'text-muted-foreground/60 hover:text-foreground'
        )}
      >
        <MinusCircle className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}
