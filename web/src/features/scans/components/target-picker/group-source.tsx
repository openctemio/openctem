'use client'

/**
 * Asset groups source of the target picker. A group's members are resolved
 * by the server when the scan runs (members outside the creator's scope are
 * skipped then), so the picker never adds its member count to the target
 * total. The count shown is the API's, which follows the viewer's scope.
 */

import { useState } from 'react'
import { Search } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { useDebounce } from '@/hooks/use-debounce'
import { useAssetGroups } from '@/features/asset-groups'

/** Asset groups listed at once (the API's largest page). */
export const GROUP_PAGE_SIZE = 100

interface GroupSourceProps {
  /** Picked group names by id. */
  selected: Record<string, string>
  onToggle: (group: { id: string; name: string }, picked: boolean) => void
}

export function GroupSource({ selected, onToggle }: GroupSourceProps) {
  const [search, setSearch] = useState('')
  const debounced = useDebounce(search, 300)
  const { data, total, isLoading } = useAssetGroups({
    filters: {
      per_page: GROUP_PAGE_SIZE,
      sort_by: 'name',
      sort_order: 'asc',
      search: debounced || undefined,
    },
  })
  const groups = data ?? []

  return (
    <div className="space-y-3">
      <div className="relative">
        <Search
          className="text-muted-foreground absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2"
          aria-hidden
        />
        <Input
          placeholder="Search asset groups..."
          aria-label="Search asset groups"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="ps-10"
        />
      </div>
      <div
        className="max-h-72 overflow-y-auto rounded-md border"
        role="group"
        aria-label="Asset groups"
      >
        {isLoading ? (
          <div className="space-y-2 p-2">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : groups.length === 0 ? (
          <p className="text-muted-foreground p-4 text-center text-sm">
            {debounced ? `No asset groups match "${debounced}"` : 'No asset groups yet.'}
          </p>
        ) : (
          <ul className="divide-y">
            {groups.map((g) => {
              const picked = selected[g.id] !== undefined
              return (
                <li key={g.id}>
                  <label
                    className={cn(
                      'flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted/50',
                      picked && 'bg-primary/5'
                    )}
                  >
                    <Checkbox
                      checked={picked}
                      onCheckedChange={(c) => onToggle({ id: g.id, name: g.name }, c === true)}
                      aria-label={g.name}
                    />
                    <span className="min-w-0 flex-1 truncate text-sm" title={g.name}>
                      {g.name}
                    </span>
                    <Badge variant="outline" className="shrink-0 text-xs">
                      {(g.assetCount ?? 0).toLocaleString()}{' '}
                      {g.assetCount === 1 ? 'asset' : 'assets'}
                    </Badge>
                  </label>
                </li>
              )
            })}
          </ul>
        )}
      </div>
      <p className="text-muted-foreground text-xs">
        {total > groups.length
          ? `Showing ${groups.length} of ${total} groups: search to find the others. `
          : ''}
        A group&apos;s members are resolved when the scan runs.
      </p>
    </div>
  )
}
