'use client'

/**
 * Create, edit and delete for the inventory (research/77): the forms are
 * generated from the asset type's registry attributes (lib/type-form), so
 * every type is created and edited the same way, from the one list.
 *
 * Writes go through the shared API client (tenant from the session, CSRF)
 * and the API gates them: POST/PUT need assets:write, DELETE assets:delete;
 * a delete the API refuses because the asset has findings offers Archive
 * (lib/safe-delete).
 */
import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { post } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { inSentence, typeViewOf, type TypeView } from '@/features/asset-types/lib/type-view'
import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'
import { AssetFormDialogShared } from '../asset-form-dialog-shared'
import { AssetDeleteDialogShared } from '../asset-delete-dialog-shared'
import { createAsset, updateAsset } from '../../hooks/use-assets'
import { deleteAssetSafely } from '../../lib/safe-delete'
import { toastIfDuplicateAsset } from '../../lib/duplicate-asset'
import { createInputFromForm, formFieldsForType, updateInputFromForm } from '../../lib/type-form'
import type { Asset } from '../../types'

/** The view an asset is edited with; without the registry only the common fields. */
function viewForAsset(registry: AssetTypeRegistry | undefined, asset: Asset): TypeView {
  return (
    typeViewOf(registry, [asset.type], asset.subType) ?? {
      type: asset.type,
      subType: asset.subType,
      label: asset.type,
      plural: asset.type,
      attributes: [],
      columns: [],
      facets: [],
      scannable: false,
    }
  )
}

export function useInventoryAssetForms(
  registry: AssetTypeRegistry | undefined,
  onChanged: () => void
): {
  openCreate: (view: TypeView) => void
  openEdit: (asset: Asset) => void
  openDelete: (asset: Asset) => void
  dialogs: ReactNode
} {
  const router = useRouter()
  const { locale } = useTranslation()
  const [createView, setCreateView] = useState<TypeView | null>(null)
  const [editing, setEditing] = useState<{ asset: Asset; view: TypeView } | null>(null)
  const [deleting, setDeleting] = useState<Asset | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const createFields = useMemo(
    () => (createView ? formFieldsForType(createView, locale) : []),
    [createView, locale]
  )
  const editFields = useMemo(
    () => (editing ? formFieldsForType(editing.view, locale) : []),
    [editing, locale]
  )

  const submitCreate = useCallback(
    async (data: Record<string, unknown>) => {
      if (!createView) return false
      setSubmitting(true)
      try {
        const created = await createAsset(createInputFromForm(createView, data))
        const groupId = typeof data.groupId === 'string' ? data.groupId.trim() : ''
        // Group membership is its own relation, added once the asset exists.
        if (groupId) {
          await post(`/api/v1/asset-groups/${encodeURIComponent(groupId)}/assets`, {
            asset_ids: [created.id],
          })
        }
        toast.success(`${createView.label} added`)
        onChanged()
        return true
      } catch (err) {
        if (!toastIfDuplicateAsset(err, router.push)) {
          toast.error(getErrorMessage(err, `Failed to add the ${inSentence(createView.label)}`))
        }
        return false
      } finally {
        setSubmitting(false)
      }
    },
    [createView, onChanged, router.push]
  )

  const submitEdit = useCallback(
    async (data: Record<string, unknown>) => {
      if (!editing) return false
      setSubmitting(true)
      try {
        await updateAsset(
          editing.asset.id,
          updateInputFromForm(editing.view, data, editing.asset.metadata)
        )
        toast.success(`${editing.asset.name} updated`)
        onChanged()
        return true
      } catch (err) {
        toast.error(getErrorMessage(err, 'Failed to update the asset'))
        return false
      } finally {
        setSubmitting(false)
      }
    },
    [editing, onChanged]
  )

  const confirmDelete = useCallback(async () => {
    if (!deleting) return
    setSubmitting(true)
    try {
      const result = await deleteAssetSafely(deleting.id, deleting.name, onChanged)
      if (result !== 'failed') setDeleting(null)
    } finally {
      setSubmitting(false)
    }
  }, [deleting, onChanged])

  const dialogs = (
    <>
      <AssetFormDialogShared
        open={!!createView}
        onOpenChange={(o) => !o && setCreateView(null)}
        title={`Add ${createView ? inSentence(createView.label) : 'asset'}`}
        description="Fields left empty stay unknown; scans fill them in."
        fields={createFields}
        assetType={createView?.type}
        onSubmit={submitCreate}
        isSubmitting={submitting}
        includeGroupSelect
      />
      <AssetFormDialogShared
        open={!!editing}
        onOpenChange={(o) => !o && setEditing(null)}
        title={`Edit ${editing?.asset.name ?? ''}`}
        fields={editFields}
        asset={editing?.asset}
        assetType={editing?.asset.type}
        onSubmit={submitEdit}
        isSubmitting={submitting}
      />
      <AssetDeleteDialogShared
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        assetName={deleting?.name}
        typeName="asset"
        onConfirm={() => void confirmDelete()}
        isSubmitting={submitting}
      />
    </>
  )

  return {
    openCreate: setCreateView,
    openEdit: (asset) => setEditing({ asset, view: viewForAsset(registry, asset) }),
    openDelete: setDeleting,
    dialogs,
  }
}
