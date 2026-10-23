/**
 * "Add assets" for one group, from the groups list. The inventory is searched
 * on the server (one page of results at a time), and the assets already in the
 * group are left out.
 */
'use client'

import { useMemo, useState } from 'react'
import { Package, Search as SearchIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { EmptyState, RiskScoreBadge } from '@/features/shared'
import { useAssets } from '@/features/assets/hooks/use-assets'
import type { Asset } from '@/features/assets/types'
import { useDebounce } from '@/hooks/use-debounce'
import { useTranslation } from '@/context/i18n-provider'
import { useAddAssetsToGroup, useGroupAssets } from '../hooks/use-asset-groups'
import type { AssetGroup } from '../types'

export function GroupAddAssetsDialog({
  group,
  onClose,
  onSuccess,
}: {
  group: AssetGroup
  onClose: () => void
  onSuccess: () => void
}) {
  const { t } = useTranslation()
  const { trigger: addAssets, isMutating } = useAddAssetsToGroup(group.id)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebounce(search.trim(), 300)
  // The server searches the whole inventory; the dialog never holds more than
  // one page of results, minus the assets already in the group.
  const {
    assets: found,
    total,
    isLoading,
  } = useAssets({
    search: debouncedSearch || undefined,
    pageSize: 20,
  })
  const { data: members } = useGroupAssets(group.id, { per_page: 100 })
  const memberIds = useMemo(() => new Set(members.map((m) => m.id)), [members])
  const displayed: Asset[] = useMemo(
    () => found.filter((a) => !memberIds.has(a.id)),
    [found, memberIds]
  )

  const handleSubmit = async () => {
    try {
      await addAssets(selectedIds)
      onSuccess()
    } catch {
      // Error handled by hook
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {t('assetGroups.addAssets.title', 'Add assets to "{name}"', { name: group.name })}
          </DialogTitle>
          <DialogDescription>
            {t('assetGroups.addAssets.description', 'Select assets to add to this group.')}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4">
            <div className="relative">
              <SearchIcon className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={t('assetGroups.addAssets.search', 'Search assets...')}
                aria-label={t('assetGroups.addAssets.search', 'Search assets...')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="ps-9"
              />
            </div>

            <div className="max-h-64 overflow-y-auto rounded-lg border">
              {displayed.length === 0 && !isLoading ? (
                <EmptyState
                  icon={Package}
                  title={t('assetGroups.addAssets.emptyTitle', 'No assets found')}
                  description={t('assetGroups.addAssets.emptyHint', 'Try a different search.')}
                  card={false}
                />
              ) : (
                <div className="divide-y">
                  {displayed.map((asset) => (
                    <label
                      key={asset.id}
                      className="flex cursor-pointer items-center gap-3 p-3 hover:bg-muted/50"
                    >
                      <Checkbox
                        checked={selectedIds.includes(asset.id)}
                        onCheckedChange={() =>
                          setSelectedIds((prev) =>
                            prev.includes(asset.id)
                              ? prev.filter((id) => id !== asset.id)
                              : [...prev, asset.id]
                          )
                        }
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-medium">{asset.name}</p>
                        <p className="text-sm text-muted-foreground">{asset.type}</p>
                      </div>
                      <RiskScoreBadge score={asset.riskScore} size="sm" />
                    </label>
                  ))}
                  {total > found.length && (
                    <p className="p-3 text-center text-xs text-muted-foreground">
                      {t(
                        'assetGroups.addAssets.refine',
                        'Showing {shown} of {total}. Search to narrow the list.',
                        { shown: found.length, total }
                      )}
                    </p>
                  )}
                </div>
              )}
            </div>

            {selectedIds.length > 0 && (
              <p className="text-sm text-muted-foreground">
                {t('assetGroups.addAssets.selected', '{count} selected', {
                  count: selectedIds.length,
                })}
              </p>
            )}
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isMutating}>
            {t('assetGroups.cancel', 'Cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={selectedIds.length === 0 || isMutating}>
            {isMutating
              ? t('assetGroups.addAssets.adding', 'Adding...')
              : t('assetGroups.addAssets.submit', 'Add {count} assets', {
                  count: selectedIds.length,
                })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
