'use client'

import { useRouter } from 'next/navigation'
import { useState } from 'react'
import {
  ExternalLink,
  Hash,
  Link as LinkIcon,
  Package,
  Pencil,
  RefreshCw,
  Trash2,
  X,
} from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { TooltipProvider } from '@/components/ui/tooltip'
import {
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  RiskScoreBadge,
  type DetailMenuItem,
} from '@/features/shared'
import { copyToClipboard } from '@/lib/clipboard'
import { CRITICALITY_BADGE_SOFT, type CriticalityLevel } from '@/lib/criticality-colors'
import { Can, Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useGroupAssets, useRemoveAssetsFromGroup } from '../hooks'
import type { AssetGroup } from '../types'

// ============================================
// ASSETS IN THE GROUP
// ============================================

function QuickViewAssets({ groupId, onRefresh }: { groupId: string; onRefresh?: () => void }) {
  const { data: assets, isLoading, mutate: refreshAssets } = useGroupAssets(groupId)
  const { trigger: removeAssets, isMutating: isRemoving } = useRemoveAssetsFromGroup(groupId)
  const router = useRouter()
  const [removingId, setRemovingId] = useState<string | null>(null)

  const handleRemoveAsset = async (assetId: string) => {
    setRemovingId(assetId)
    try {
      await removeAssets([assetId])
      refreshAssets()
      onRefresh?.()
    } catch {
      // Error handled by hook
    } finally {
      setRemovingId(null)
    }
  }

  const displayAssets = (assets || []).slice(0, 5)

  return (
    <DetailSection
      title="Recent assets"
      icon={Package}
      count={isLoading ? undefined : (assets?.length ?? 0)}
      actions={
        <Button
          variant="ghost"
          size="sm"
          className="h-7 text-xs"
          onClick={() => router.push(`/assets/groups/${groupId}?tab=assets`)}
        >
          Manage all
          <ExternalLink className="ms-1 h-3 w-3" />
        </Button>
      }
    >
      {isLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : displayAssets.length === 0 ? (
        <p className="text-sm text-muted-foreground">No assets in this group</p>
      ) : (
        <ul className="divide-y rounded-lg border">
          {displayAssets.map(
            (asset: { id: string; name: string; type: string; status?: string }) => {
              const status = asset.status || 'active'
              return (
                <li
                  key={asset.id}
                  className="group flex items-center justify-between gap-2 px-3 py-2 hover:bg-muted/50"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium break-all">{asset.name}</p>
                    <p className="text-xs text-muted-foreground">{asset.type}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <Badge
                      variant="outline"
                      className={cn(
                        status === 'active' && 'border-success/30 bg-success/10 text-success'
                      )}
                    >
                      {status}
                    </Badge>
                    <Can permission={Permission.AssetGroupsWrite}>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Remove ${asset.name} from the group`}
                        className="h-7 w-7 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-destructive focus-visible:opacity-100"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleRemoveAsset(asset.id)
                        }}
                        disabled={isRemoving}
                      >
                        {removingId === asset.id ? (
                          <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <X className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </Can>
                  </div>
                </li>
              )
            }
          )}
        </ul>
      )}
    </DetailSection>
  )
}

// ============================================
// QUICK VIEW SHEET
// ============================================

interface GroupQuickViewProps {
  group: AssetGroup | null
  onClose: () => void
  onEdit: (group: AssetGroup) => void
  onDelete: (group: AssetGroup) => void
  onRefresh: () => void
}

export function GroupQuickView({
  group,
  onClose,
  onEdit,
  onDelete,
  onRefresh,
}: GroupQuickViewProps) {
  const router = useRouter()
  const canWrite = useHasPermission(Permission.AssetGroupsWrite)
  const canDelete = useHasPermission(Permission.AssetGroupsDelete)
  if (!group) return null

  const menu: DetailMenuItem[] = [
    {
      label: 'Copy ID',
      icon: Hash,
      onSelect: () => {
        copyToClipboard(group.id)
        toast.success('Group ID copied')
      },
    },
    {
      label: 'Copy link',
      icon: LinkIcon,
      onSelect: () => {
        copyToClipboard(`${window.location.origin}/assets/groups/${group.id}`)
        toast.success('Link copied to clipboard')
      },
    },
  ]
  if (canDelete) {
    menu.push({
      label: 'Delete group',
      icon: Trash2,
      destructive: true,
      separatorBefore: true,
      onSelect: () => {
        onClose()
        onDelete(group)
      },
    })
  }

  const criticality = group.criticality as CriticalityLevel

  return (
    <TooltipProvider>
      <DetailSheet
        open
        onOpenChange={(open) => !open && onClose()}
        header={
          <DetailHeader
            title={group.name}
            badges={
              <>
                <Badge variant="secondary" className="capitalize">
                  {group.environment}
                </Badge>
                <Badge
                  variant="outline"
                  className={cn('capitalize', CRITICALITY_BADGE_SOFT[criticality])}
                >
                  {group.criticality}
                </Badge>
              </>
            }
            meta={['Asset group', group.owner ? `owner ${group.owner}` : 'no owner']}
            actions={
              <>
                {canWrite && (
                  <Button
                    size="sm"
                    onClick={() => {
                      onClose()
                      onEdit(group)
                    }}
                  >
                    <Pencil className="h-4 w-4" />
                    Edit
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    onClose()
                    router.push(`/assets/groups/${group.id}`)
                  }}
                >
                  <ExternalLink className="h-4 w-4" />
                  Open full page
                </Button>
              </>
            }
            menu={menu}
            onClose={onClose}
          />
        }
      >
        <div className="space-y-5">
          <DetailStatGrid aria-label="Key numbers">
            <DetailStat label="Assets" value={group.assetCount} />
            <DetailStat
              label="Findings"
              value={group.findingCount}
              tone={group.findingCount > 0 ? 'warning' : 'default'}
            />
            <DetailStat label="Risk" value={<RiskScoreBadge score={group.riskScore} />} />
          </DetailStatGrid>

          <DetailSections>
            {group.description && (
              <DetailSection title="Description">
                <p className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground">
                  {group.description}
                </p>
              </DetailSection>
            )}

            <QuickViewAssets groupId={group.id} onRefresh={onRefresh} />

            <DetailSection title="Details">
              <DetailFieldGrid>
                <DetailField label="Owner">{group.owner || 'Not assigned'}</DetailField>
                <DetailField label="Created">
                  {new Date(group.createdAt).toLocaleDateString()}
                </DetailField>
                <DetailField label="Last updated">
                  {new Date(group.updatedAt).toLocaleDateString()}
                </DetailField>
                <DetailField label="ID" full>
                  <DetailCopyId id={group.id} label="Group ID" />
                </DetailField>
              </DetailFieldGrid>
            </DetailSection>
          </DetailSections>
        </div>
      </DetailSheet>
    </TooltipProvider>
  )
}
