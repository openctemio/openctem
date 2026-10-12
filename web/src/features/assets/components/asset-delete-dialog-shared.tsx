'use client'

/**
 * The one confirmation for deleting an asset, used by every page that
 * deletes one. Deletes go through features/assets/lib/safe-delete.
 */

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

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
  const { t } = useTranslation()
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={
        assetName
          ? t('confirm.asset.deleteTitle', 'Delete the {type} "{name}"?', {
              type: typeName.toLowerCase(),
              name: assetName,
            })
          : t('confirm.asset.deleteTitleUnnamed', 'Delete this {type}?', {
              type: typeName.toLowerCase(),
            })
      }
      desc={t(
        'confirm.asset.deleteDesc',
        'It leaves every list and its name can be used again. An asset that has findings is not deleted: archive it instead, so its finding history is kept.'
      )}
      confirmText={
        isSubmitting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
      }
      destructive
      isLoading={isSubmitting}
      handleConfirm={onConfirm}
    />
  )
}
