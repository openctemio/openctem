'use client'

/**
 * Asset Relationships Tab
 *
 * Self-contained tab for an asset detail sheet: the grouped related-assets
 * list (RelatedAssetsList), an optional graph for small neighbourhoods, and
 * the add / edit / remove flows. The parent passes the asset and a navigate
 * callback; fetching, dialogs, mutations and toasts live here.
 */

import { useCallback, useMemo, useState } from 'react'
import { List, Network, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Slider } from '@/components/ui/slider'
import { Textarea } from '@/components/ui/textarea'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { get } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  addAssetRelationshipBatch,
  getAssetRelationship,
  removeAssetRelationship,
  updateAssetRelationship,
  useAssetRelationships,
} from '../hooks/use-asset-relationships'
import { useRelatedAssets, type RelatedAssetItem } from '../hooks/use-related-assets'
import { relationVerbFallback, relationVerbKey } from '../lib/relationship-verbs'
import type {
  Asset,
  AssetRelationship,
  CreateRelationshipInput,
  ExtendedAssetType,
  RelationshipConfidence,
} from '../types'
import {
  RELATED_PREVIEW_ROWS,
  RelatedAssetsList,
  revalidateRelatedAssets,
} from './relationships/related-assets-list'
import {
  RelationshipGraphView,
  buildGraphFromRelationships,
} from './relationships/relationship-graph'
import { AddRelationshipDialog, type AssetOption } from './relationships/add-relationship-dialog'

interface AssetRelationshipsTabProps {
  assetId: string
  /** The current asset is the source for any new relationship. */
  sourceAsset: Pick<Asset, 'id' | 'name' | 'type' | 'subType'>
  /** Opens a related asset; the sheet keeps the back trail. */
  onNavigateToAsset?: (assetId: string, name: string) => void
}

interface BackendAssetSearchItem {
  id: string
  name: string
  type: string
  sub_type?: string
  description?: string
}
interface BackendAssetsListResponse {
  data: BackendAssetSearchItem[]
  total: number
}

const PICKER_PAGE_SIZE = 50
/**
 * The graph is offered only for a neighbourhood it can draw legibly; a larger
 * one is read through the grouped list (counts, search, paging).
 */
const GRAPH_MAX_EDGES = 30

export function AssetRelationshipsTab({
  assetId,
  sourceAsset,
  onNavigateToAsset,
}: AssetRelationshipsTabProps) {
  const { t } = useTranslation()
  // The flat list feeds the add dialog's duplicate check and the small graph.
  const { relationships, mutate } = useAssetRelationships(assetId)
  const { total } = useRelatedAssets(assetId, { limit: RELATED_PREVIEW_ROWS })
  const { can } = usePermissions()
  const { currentTenant } = useTenant()
  const canWrite = can(Permission.AssetsWrite)
  const canDelete = can(Permission.AssetsDelete)

  const [view, setView] = useState<'list' | 'graph'>('list')
  const graphAvailable = total > 0 && total <= GRAPH_MAX_EDGES
  const graphData = useMemo(
    () =>
      buildGraphFromRelationships(relationships, (type) =>
        t(relationVerbKey(type, 'outgoing'), relationVerbFallback(type, 'outgoing'))
      ),
    [relationships, t]
  )

  const [showAddDialog, setShowAddDialog] = useState(false)
  const [editTarget, setEditTarget] = useState<AssetRelationship | null>(null)
  const [removeTarget, setRemoveTarget] = useState<RelatedAssetItem | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const [editDescription, setEditDescription] = useState('')
  const [editConfidence, setEditConfidence] = useState<RelationshipConfidence>('medium')
  const [editImpactWeight, setEditImpactWeight] = useState(5)
  const [editIsControlPlane, setEditIsControlPlane] = useState(false)

  const refresh = useCallback(() => {
    void mutate()
    void revalidateRelatedAssets(assetId)
  }, [assetId, mutate])

  const verb = (type: string, direction: 'outgoing' | 'incoming') =>
    t(relationVerbKey(type, direction), relationVerbFallback(type, direction))

  // Server-side asset search for the Add dialog (the dialog applies the
  // registry's type constraints on top).
  const searchAssets = useCallback(
    async (query: string): Promise<AssetOption[]> => {
      if (!currentTenant) return []
      const params = new URLSearchParams({ per_page: String(PICKER_PAGE_SIZE) })
      if (query.trim()) params.set('search', query.trim())
      try {
        const response = await get<BackendAssetsListResponse>(`/api/v1/assets?${params.toString()}`)
        return (response.data ?? []).map((a) => ({
          id: a.id,
          name: a.name,
          type: a.type as ExtendedAssetType,
          subType: a.sub_type,
          description: a.description,
        }))
      } catch {
        return []
      }
    },
    [currentTenant]
  )

  const names = (list: string[], max = 3) =>
    list.length <= max
      ? list.join(', ')
      : t('assets.related.toast.namesMore', '{names}, and {count} more', {
          names: list.slice(0, max).join(', '),
          count: list.length - max,
        })

  const handleAdd = async (
    items: Array<{ input: CreateRelationshipInput; targetName: string }>
  ) => {
    if (items.length === 0) return
    setIsSubmitting(true)
    try {
      const result = await addAssetRelationshipBatch(
        assetId,
        items.map((it) => it.input)
      )

      // The batch endpoint does not take the control-plane flag: set it on
      // the edges just created.
      const controlPlaneUpdates = result.results
        .filter(
          (r) =>
            r.status === 'created' &&
            !!r.relationship_id &&
            items[r.index]?.input.isControlPlane === true
        )
        .map((r) => updateAssetRelationship(r.relationship_id as string, { isControlPlane: true }))
      if (controlPlaneUpdates.length > 0) {
        const settled = await Promise.allSettled(controlPlaneUpdates)
        if (settled.some((s) => s.status === 'rejected')) {
          toast.warning(
            t(
              'assets.related.toast.controlPlanePartial',
              'Created, but some relationships could not be marked as control plane. Edit them to set it.'
            )
          )
        }
      }

      const created: string[] = []
      const duplicates: string[] = []
      const failed: string[] = []
      const errors: string[] = []
      result.results.forEach((r) => {
        const name = items[r.index]?.targetName ?? '?'
        if (r.status === 'created') created.push(name)
        else if (r.status === 'duplicate') duplicates.push(name)
        else {
          failed.push(name)
          if (r.error) errors.push(r.error)
        }
      })

      const n = items.length
      if (created.length === n) {
        toast.success(
          t('assets.related.toast.created', '{count} relationships added', { count: n })
        )
        setShowAddDialog(false)
      } else if (created.length === 0 && failed.length === 0) {
        toast.error(t('assets.related.toast.allExist', 'Already recorded'), {
          description: names(duplicates),
        })
      } else if (created.length === 0) {
        toast.error(
          errors[0] || t('assets.related.toast.createFailed', 'Could not add the relationships'),
          {
            description: failed.length > 1 ? names(failed) : undefined,
          }
        )
      } else {
        toast.warning(
          t('assets.related.toast.partial', '{created} of {total} added', {
            created: created.length,
            total: n,
          }),
          {
            description: t(
              'assets.related.toast.partialDetail',
              '{duplicates} already recorded, {failed} failed',
              { duplicates: duplicates.length, failed: failed.length }
            ),
          }
        )
        setShowAddDialog(false)
      }
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('assets.related.toast.createFailed', 'Could not add the relationships')
        )
      )
    } finally {
      setIsSubmitting(false)
      refresh()
    }
  }

  const openEditDialog = async (item: RelatedAssetItem) => {
    try {
      const rel = await getAssetRelationship(item.relationship_id)
      setEditTarget(rel)
      setEditDescription(rel.description ?? '')
      setEditConfidence(rel.confidence)
      setEditImpactWeight(rel.impactWeight)
      setEditIsControlPlane(rel.isControlPlane ?? false)
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('assets.related.toast.loadFailed', 'Could not load the relationship')
        )
      )
    }
  }

  const handleEdit = async () => {
    if (!editTarget) return
    setIsSubmitting(true)
    try {
      await updateAssetRelationship(editTarget.id, {
        description: editDescription,
        confidence: editConfidence,
        impactWeight: editImpactWeight,
        isControlPlane: editIsControlPlane,
      })
      toast.success(t('assets.related.toast.updated', 'Relationship updated'))
      setEditTarget(null)
      refresh()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('assets.related.toast.updateFailed', 'Could not update the relationship')
        )
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleRemove = async () => {
    if (!removeTarget) return
    setIsSubmitting(true)
    try {
      await removeAssetRelationship(removeTarget.relationship_id)
      toast.success(t('assets.related.toast.removed', 'Relationship removed'))
      setRemoveTarget(null)
      refresh()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('assets.related.toast.removeFailed', 'Could not remove the relationship')
        )
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  const addButton = canWrite ? (
    <Button size="sm" variant="outline" onClick={() => setShowAddDialog(true)}>
      <Plus className="mr-1 h-4 w-4" />
      {t('assets.related.add', 'Add relationship')}
    </Button>
  ) : null

  const editingOutgoing = editTarget?.sourceAssetId === assetId

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {graphAvailable ? (
          <div
            role="group"
            aria-label={t('assets.related.viewLabel', 'View')}
            className="inline-flex rounded-md border p-0.5"
          >
            {(['list', 'graph'] as const).map((v) => {
              const Icon = v === 'list' ? List : Network
              const label =
                v === 'list'
                  ? t('assets.related.viewList', 'List')
                  : t('assets.related.viewGraph', 'Graph')
              return (
                <Button
                  key={v}
                  type="button"
                  size="sm"
                  variant={view === v ? 'secondary' : 'ghost'}
                  className="h-7 px-2"
                  aria-pressed={view === v}
                  onClick={() => setView(v)}
                >
                  <Icon className="h-4 w-4" aria-hidden />
                  <span className="ml-1">{label}</span>
                </Button>
              )
            })}
          </div>
        ) : (
          <span />
        )}
        {total > 0 && addButton}
      </div>

      {view === 'graph' && graphAvailable ? (
        <div className="space-y-2">
          <div className="h-[360px]">
            <RelationshipGraphView
              className="h-full"
              graph={graphData}
              centralNodeId={assetId}
              onNodeClick={(nodeId) => {
                const node = graphData.nodes.find((n) => n.id === nodeId)
                if (node && nodeId !== assetId) onNavigateToAsset?.(nodeId, node.name)
              }}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'assets.related.graphHint',
              'The list is the complete, accessible view; the graph draws the same relationships around this asset.'
            )}
          </p>
        </div>
      ) : (
        <RelatedAssetsList
          assetId={assetId}
          onNavigateToAsset={onNavigateToAsset}
          onEdit={canWrite ? openEditDialog : undefined}
          onRemove={canDelete ? setRemoveTarget : undefined}
          addAction={addButton}
        />
      )}

      <AddRelationshipDialog
        open={showAddDialog}
        onOpenChange={setShowAddDialog}
        sourceAsset={{
          id: sourceAsset.id,
          name: sourceAsset.name,
          type: sourceAsset.type as ExtendedAssetType,
          subType: sourceAsset.subType,
        }}
        searchAssets={searchAssets}
        existingRelationships={relationships}
        onSubmit={handleAdd}
        isLoading={isSubmitting}
      />

      <Dialog
        open={!!editTarget}
        onOpenChange={(open) => {
          if (!open) setEditTarget(null)
        }}
      >
        <DialogContent
          onPointerDownOutside={(e) => e.preventDefault()}
          onInteractOutside={(e) => e.preventDefault()}
        >
          <DialogHeader>
            <DialogTitle>{t('assets.related.editTitle', 'Edit relationship')}</DialogTitle>
            <DialogDescription>
              {t(
                'assets.related.editDescription',
                'The two assets and the kind of relationship cannot change: remove it and add a new one instead.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              {editTarget && (
                <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/30 p-3 text-sm">
                  <Badge variant="secondary" className="max-w-[200px] truncate">
                    {sourceAsset.name}
                  </Badge>
                  <span className="text-muted-foreground">
                    {verb(editTarget.type, editingOutgoing ? 'outgoing' : 'incoming')}
                  </span>
                  <Badge variant="secondary" className="max-w-[200px] truncate">
                    {editingOutgoing ? editTarget.targetAssetName : editTarget.sourceAssetName}
                  </Badge>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="rel-edit-description">
                  {t('assets.related.fieldDescription', 'Description')}
                </Label>
                <Textarea
                  id="rel-edit-description"
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                  rows={3}
                  placeholder={t(
                    'assets.related.fieldDescriptionHint',
                    'Optional context for this relationship'
                  )}
                />
              </div>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label>{t('assets.related.fieldConfidence', 'Confidence')}</Label>
                  <Select
                    value={editConfidence}
                    onValueChange={(v) => setEditConfidence(v as RelationshipConfidence)}
                  >
                    <SelectTrigger aria-label={t('assets.related.fieldConfidence', 'Confidence')}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="high">
                        {t('assets.related.confidence.high', 'High')}
                      </SelectItem>
                      <SelectItem value="medium">
                        {t('assets.related.confidence.medium', 'Medium')}
                      </SelectItem>
                      <SelectItem value="low">
                        {t('assets.related.confidence.low', 'Low')}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>
                    {t('assets.related.fieldImpact', 'Impact on attack paths: {value}', {
                      value: editImpactWeight,
                    })}
                  </Label>
                  <Slider
                    value={[editImpactWeight]}
                    onValueChange={([v]) => setEditImpactWeight(v)}
                    min={1}
                    max={10}
                    step={1}
                    className="mt-2"
                    aria-label={t('assets.related.fieldImpactShort', 'Impact')}
                  />
                </div>
              </div>

              <div className="flex items-start gap-2 rounded-lg border p-3">
                <Checkbox
                  id="edit-is-control-plane"
                  checked={editIsControlPlane}
                  onCheckedChange={(checked) => setEditIsControlPlane(checked === true)}
                  className="mt-0.5"
                />
                <div className="space-y-0.5">
                  <Label
                    htmlFor="edit-is-control-plane"
                    className="cursor-pointer text-sm font-normal"
                  >
                    {t(
                      'assets.related.fieldControlPlane',
                      'Control-plane dependency (identity provider, secrets, CI/CD, SIEM)'
                    )}
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'assets.related.fieldControlPlaneHint',
                      'Mark it when the other asset governs this one’s security, so scoping can trace the blast radius.'
                    )}
                  </p>
                </div>
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(null)}>
              {t('assets.related.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleEdit} disabled={isSubmitting}>
              {isSubmitting
                ? t('assets.related.saving', 'Saving…')
                : t('assets.related.save', 'Save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!removeTarget}
        onOpenChange={(open) => {
          if (!open) setRemoveTarget(null)
        }}
        title={t(
          'confirm.assetRelationship.removeTitle',
          'Remove the relationship between {source} and {target}?',
          {
            source:
              removeTarget?.direction === 'incoming' ? removeTarget.asset.name : sourceAsset.name,
            target:
              removeTarget?.direction === 'incoming'
                ? sourceAsset.name
                : (removeTarget?.asset.name ?? ''),
          }
        )}
        desc={t(
          'confirm.assetRelationship.removeDesc',
          'Only the link between them is removed; both assets stay. This cannot be undone.'
        )}
        confirmText={
          isSubmitting ? t('confirm.removing', 'Removing…') : t('confirm.remove', 'Remove')
        }
        destructive
        isLoading={isSubmitting}
        handleConfirm={handleRemove}
      />
    </div>
  )
}
