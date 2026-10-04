'use client'

/**
 * The one confirmation for deleting an asset, used by every page that
 * deletes one. Deletes go through features/assets/lib/safe-delete.
 */

import { ConfirmDialog } from '@/components/confirm-dialog'

interface AssetDeleteDialogSharedProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  assetName?: string
  typeName: string
  onConfirm: () => void
  isSubmitting?: boolean
}

export function AssetDeleteDialogShared({
  open,
  onOpenChange,
  assetName,
  typeName,
  onConfirm,
  isSubmitting,
}: AssetDeleteDialogSharedProps) {
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Delete ${typeName}`}
      desc={
        <>
          Delete {assetName ? `"${assetName}"` : `this ${typeName.toLowerCase()}`}? It leaves every
          list and its name can be used again. An asset that has findings is not deleted: archive it
          instead, so its finding history is kept.
        </>
      }
      confirmText={isSubmitting ? 'Deleting...' : 'Delete'}
      destructive
      isLoading={isSubmitting}
      handleConfirm={onConfirm}
    />
  )
}
