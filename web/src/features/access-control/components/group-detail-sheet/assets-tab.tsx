import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Input } from '@/components/ui/input'
import {
  Box,
  Plus,
  Trash2,
  Search,
  Globe,
  Database,
  Server,
  Cloud,
  Layers,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { DataTableRowActions, EmptyState } from '@/features/shared'
import { type GroupAsset } from '@/features/access-control'
import { useState, useEffect } from 'react'

interface AssetsTabProps {
  assets: GroupAsset[]
  totalCount: number
  isLoading: boolean
  limit: number
  offset: number
  onPageChange: (offset: number) => void
  /** The three callbacks are omitted when the caller may not change the
   *  team's assets; their controls are then hidden. */
  onAddAsset?: () => void
  onBulkAddAssets?: () => void
  onRemoveAsset?: (id: string, name: string) => void
}

export function AssetsTab({
  assets,
  totalCount,
  isLoading,
  limit,
  offset,
  onPageChange,
  onAddAsset,
  onBulkAddAssets,
  onRemoveAsset,
}: AssetsTabProps) {
  const [searchQuery, setSearchQuery] = useState('')

  // Reset to first page when search query changes
  useEffect(() => {
    if (searchQuery) {
      onPageChange(0)
    }
  }, [searchQuery, onPageChange])

  const filteredAssets = searchQuery
    ? assets.filter(
        (item) =>
          item.asset?.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          item.asset?.type.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : assets

  const currentPage = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(totalCount / limit)

  const getAssetIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'domain':
        return <Globe className="h-4 w-4 text-muted-foreground" />
      case 'repository':
        return <Database className="h-4 w-4 text-muted-foreground" />
      case 'host':
        return <Server className="h-4 w-4 text-muted-foreground" />
      case 'cloud':
        return <Cloud className="h-4 w-4 text-muted-foreground" />
      default:
        return <Box className="h-4 w-4 text-muted-foreground" />
    }
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-medium">Assigned Assets ({totalCount})</h4>
        <div className="flex items-center gap-2">
          {onBulkAddAssets && (
            <Button size="sm" variant="outline" onClick={onBulkAddAssets}>
              <Layers className="me-2 h-4 w-4" />
              Bulk Add
            </Button>
          )}
          {onAddAsset && (
            <Button size="sm" onClick={onAddAsset}>
              <Plus className="me-2 h-4 w-4" />
              Assign Asset
            </Button>
          )}
        </div>
      </div>

      <div className="relative mb-4">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search assets..."
          className="ps-9"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : totalCount === 0 ? (
        <EmptyState icon={Box} title="No assets assigned to this group" card={false} />
      ) : filteredAssets.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <p>No assets found matching &quot;{searchQuery}&quot;</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredAssets.map((item) => (
            <div
              key={item.id}
              className="flex items-center justify-between p-3 rounded-lg border hover:bg-muted/50 transition-colors"
            >
              <div className="flex min-w-0 items-center gap-3">
                <div className="shrink-0 rounded-lg bg-muted p-2">
                  {getAssetIcon(item.asset?.type || 'unknown')}
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-medium break-all">
                      {item.asset?.name || 'Unknown Asset'}
                    </p>
                    <Badge variant="outline" className="text-xs capitalize">
                      {item.ownership_type} Owner
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="capitalize">{item.asset?.type || 'Unknown Type'}</span>
                    <span>•</span>
                    <span className="capitalize">{item.asset?.status || 'Unknown Status'}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {onRemoveAsset && (
                  <DataTableRowActions
                    actions={[
                      {
                        label: 'Remove',
                        icon: Trash2,
                        destructive: true,
                        onClick: () => onRemoveAsset(item.asset_id, item.asset?.name || 'Asset'),
                      },
                    ]}
                  />
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4 pt-4 border-t">
          <span className="text-xs text-muted-foreground">
            Page {currentPage} of {totalPages} ({totalCount} total)
          </span>
          <div className="flex items-center gap-1">
            <Button
              size="sm"
              variant="outline"
              disabled={offset === 0}
              onClick={() => onPageChange(Math.max(0, offset - limit))}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={offset + limit >= totalCount}
              onClick={() => onPageChange(offset + limit)}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
