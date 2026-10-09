'use client'

/**
 * Assets source of the target picker: the inventory as the API returns it
 * for this user (data scope applies server-side), searched and filtered on
 * the server, a page at a time. Select a row, a page, a shift-click range,
 * or every asset matching the filter (up to the scan's direct-target limit).
 */

import { useMemo, useRef, useState } from 'react'
import { ChevronLeft, ChevronRight, Loader2, Search } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { useDebounce } from '@/hooks/use-debounce'
import { getErrorMessage } from '@/lib/api/error-handler'
import { ASSET_TYPE_COLORS, ASSET_TYPE_LABELS, useAssets } from '@/features/assets'
import type { Asset, AssetType } from '@/features/assets'
import { fetchAllAssets } from '@/features/assets/hooks/use-assets'
import { CRITICALITY_LABELS, type CriticalityLevel } from '@/lib/criticality'
import { MAX_DIRECT_TARGETS } from '../../lib/scan-form'

export const ASSET_PAGE_SIZE = 25
const ALL = 'all'

/** A picked asset as the picker keeps it. */
export interface PickedAsset {
  id: string
  name: string
}

interface AssetSourceProps {
  /** Picked asset names by id. */
  selected: Record<string, string>
  onChange: (assets: PickedAsset[], picked: boolean) => void
}

export function AssetSource({ selected, onChange }: AssetSourceProps) {
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebounce(search, 300)
  const [type, setType] = useState<string>(ALL)
  const [criticality, setCriticality] = useState<string>(ALL)
  const [selectedOnly, setSelectedOnly] = useState(false)
  const [page, setPage] = useState(1)
  const [selectingAll, setSelectingAll] = useState(false)
  const lastIndex = useRef<number | null>(null)
  // Whether the pointer that toggled a row held Shift (a range pick).
  const shiftHeld = useRef(false)

  const filters = useMemo(
    () => ({
      search: debouncedSearch || undefined,
      types: type === ALL ? undefined : [type as AssetType],
      criticalities: criticality === ALL ? undefined : [criticality as CriticalityLevel],
    }),
    [debouncedSearch, type, criticality]
  )
  const { assets, total, totalPages, isLoading, isError, error } = useAssets({
    ...filters,
    page,
    pageSize: ASSET_PAGE_SIZE,
    skip: selectedOnly,
  })

  const selectedRows: PickedAsset[] = useMemo(
    () => Object.entries(selected).map(([id, name]) => ({ id, name })),
    [selected]
  )
  const rows: PickedAsset[] = selectedOnly
    ? selectedRows
    : assets.map((a: Asset) => ({ id: a.id, name: a.name }))
  const meta = useMemo(() => new Map(assets.map((a: Asset) => [a.id, a])), [assets])
  const pageSelected = rows.length > 0 && rows.every((r) => selected[r.id] !== undefined)
  const someSelected = rows.some((r) => selected[r.id] !== undefined)

  const resetPage = () => {
    setPage(1)
    lastIndex.current = null
  }

  const toggleRow = (index: number, picked: boolean, shift: boolean) => {
    if (shift && lastIndex.current !== null && lastIndex.current !== index) {
      const [from, to] = [Math.min(lastIndex.current, index), Math.max(lastIndex.current, index)]
      onChange(rows.slice(from, to + 1), picked)
    } else {
      onChange([rows[index]], picked)
    }
    lastIndex.current = index
  }

  const selectAllMatching = async () => {
    setSelectingAll(true)
    try {
      const all = await fetchAllAssets(filters)
      const capped = all.slice(0, MAX_DIRECT_TARGETS)
      onChange(
        capped.map((a) => ({ id: a.id, name: a.name })),
        true
      )
      if (all.length > capped.length) {
        toast.warning(
          `Selected the first ${MAX_DIRECT_TARGETS.toLocaleString()} of ${all.length.toLocaleString()} assets: a scan takes at most ${MAX_DIRECT_TARGETS.toLocaleString()} direct targets. Narrow the filter, or scan an asset group.`
        )
      }
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not load the matching assets'))
    } finally {
      setSelectingAll(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="relative flex-1">
          <Search
            className="text-muted-foreground absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2"
            aria-hidden
          />
          <Input
            placeholder="Search assets by name..."
            aria-label="Search assets"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              resetPage()
            }}
            className="ps-10"
            disabled={selectedOnly}
          />
        </div>
        <Select
          value={type}
          onValueChange={(v) => {
            setType(v)
            resetPage()
          }}
          disabled={selectedOnly}
        >
          <SelectTrigger className="w-full sm:w-36" aria-label="Asset type">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All types</SelectItem>
            {Object.entries(ASSET_TYPE_LABELS).map(([value, label]) => (
              <SelectItem key={value} value={value}>
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={criticality}
          onValueChange={(v) => {
            setCriticality(v)
            resetPage()
          }}
          disabled={selectedOnly}
        >
          <SelectTrigger className="w-full sm:w-36" aria-label="Criticality">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Any criticality</SelectItem>
            {Object.entries(CRITICALITY_LABELS).map(([value, label]) => (
              <SelectItem key={value} value={value}>
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <label className="flex items-center gap-2 text-sm">
          <Checkbox
            checked={pageSelected ? true : someSelected ? 'indeterminate' : false}
            onCheckedChange={(c) => onChange(rows, c === true)}
            disabled={rows.length === 0}
            aria-label={selectedOnly ? 'Select all shown' : 'Select this page'}
          />
          <span className="text-muted-foreground">
            {selectedOnly ? 'All selected' : 'This page'}
          </span>
        </label>
        <div className="flex items-center gap-3">
          {!selectedOnly && total > rows.length && (
            <Button
              type="button"
              variant="link"
              size="sm"
              className="h-auto p-0"
              onClick={selectAllMatching}
              disabled={selectingAll}
            >
              {selectingAll && <Loader2 className="me-1 h-3 w-3 animate-spin" aria-hidden />}
              Select all {total.toLocaleString()} matching
            </Button>
          )}
          <div className="flex items-center gap-2">
            <Switch
              id="selected-only"
              checked={selectedOnly}
              onCheckedChange={(v) => {
                setSelectedOnly(v)
                lastIndex.current = null
              }}
            />
            <Label htmlFor="selected-only" className="text-sm font-normal">
              Selected only ({selectedRows.length})
            </Label>
          </div>
        </div>
      </div>

      <div
        className="max-h-72 overflow-y-auto rounded-md border"
        role="group"
        aria-label="Assets"
        aria-busy={isLoading || undefined}
      >
        {isLoading && !selectedOnly ? (
          <div className="space-y-2 p-2">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : isError && !selectedOnly ? (
          <p className="p-4 text-center text-sm text-destructive">
            {getErrorMessage(error, 'The assets could not be loaded')}
          </p>
        ) : rows.length === 0 ? (
          <p className="text-muted-foreground p-4 text-center text-sm">
            {selectedOnly
              ? 'No asset selected yet.'
              : debouncedSearch || type !== ALL || criticality !== ALL
                ? 'No asset matches these filters.'
                : 'No assets in your inventory yet.'}
          </p>
        ) : (
          <ul className="divide-y">
            {rows.map((row, index) => {
              const asset = meta.get(row.id)
              const picked = selected[row.id] !== undefined
              const colors = asset
                ? (ASSET_TYPE_COLORS[asset.type] ?? { bg: 'bg-muted', text: 'text-foreground' })
                : null
              return (
                <li
                  key={row.id}
                  onPointerDown={(e) => {
                    shiftHeld.current = e.shiftKey
                  }}
                  onKeyDown={(e) => {
                    shiftHeld.current = e.shiftKey
                  }}
                >
                  <label
                    className={cn(
                      'flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted/50',
                      picked && 'bg-primary/5'
                    )}
                  >
                    <Checkbox
                      checked={picked}
                      onCheckedChange={(c) => {
                        // Shift + click (or Shift + Space) picks the range from the last row.
                        toggleRow(index, c === true, shiftHeld.current)
                        shiftHeld.current = false
                      }}
                      aria-label={row.name}
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium" title={row.name}>
                        {row.name}
                      </span>
                      {asset?.description && (
                        <span className="text-muted-foreground block truncate text-xs">
                          {asset.description}
                        </span>
                      )}
                    </span>
                    {asset && colors && (
                      <Badge
                        variant="outline"
                        className={cn('shrink-0 text-xs', colors.bg, colors.text)}
                      >
                        {ASSET_TYPE_LABELS[asset.type] ?? asset.type}
                      </Badge>
                    )}
                    {asset?.criticality && asset.criticality !== 'none' && (
                      <span className="text-muted-foreground hidden shrink-0 text-xs sm:inline">
                        {CRITICALITY_LABELS[asset.criticality]}
                      </span>
                    )}
                  </label>
                </li>
              )
            })}
          </ul>
        )}
      </div>

      {!selectedOnly && total > 0 && (
        <div className="flex items-center justify-between">
          <p className="text-muted-foreground text-xs">
            {total.toLocaleString()} {total === 1 ? 'asset' : 'assets'}
          </p>
          {totalPages > 1 && (
            <div className="flex items-center gap-1">
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                aria-label="Previous page"
                disabled={page <= 1 || isLoading}
                onClick={() => {
                  setPage((p) => Math.max(1, p - 1))
                  lastIndex.current = null
                }}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-muted-foreground min-w-[60px] text-center text-xs">
                {page} / {totalPages}
              </span>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                aria-label="Next page"
                disabled={page >= totalPages || isLoading}
                onClick={() => {
                  setPage((p) => Math.min(totalPages, p + 1))
                  lastIndex.current = null
                }}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
