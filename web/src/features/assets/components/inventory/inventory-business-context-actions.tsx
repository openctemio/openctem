'use client'

/**
 * Bulk "Add to business unit" and "Add to business service" for the inventory
 * selection bar, so business context can be filled in where the assets are.
 * Each action shows only when its module is on and the user holds the write
 * permission the API enforces (assets:write for units, business services
 * write for services). Links are additive: an asset can be in several units
 * and serve several services.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Building, Building2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Permission, useNavItemAccess } from '@/lib/permissions'
import {
  useBusinessUnits,
  addAssetToBusinessUnit,
} from '@/features/business-units/api/use-business-units'
import {
  DEPENDENCY_TYPES,
  linkServiceAsset,
  useBusinessServiceOptions,
  type DependencyType,
} from '@/features/business-services/api/business-service-assets'
import { linkInBatches } from '../link-assets-dialog'
import type { Asset } from '../../types/asset.types'

type Target = 'unit' | 'service'

export function InventoryBusinessContextActions({
  selected,
  onDone,
}: {
  selected: Asset[]
  onDone: () => void
}) {
  const { t } = useTranslation()
  const allowed = useNavItemAccess()
  const canUnit = allowed({ module: 'business_units', permission: Permission.AssetsWrite })
  const canService = allowed({
    module: 'business_services',
    permission: Permission.BusinessServicesWrite,
  })
  const [dialog, setDialog] = useState<Target | null>(null)
  const [targetId, setTargetId] = useState('')
  const [dependency, setDependency] = useState<DependencyType>('runs_on')
  const [submitting, setSubmitting] = useState(false)

  const { data: units } = useBusinessUnits(undefined, dialog === 'unit')
  const { data: services } = useBusinessServiceOptions(dialog === 'service')
  const options =
    dialog === 'unit'
      ? (units?.data ?? []).map((u) => ({ id: u.id, name: u.name }))
      : (services?.data ?? []).map((s) => ({ id: s.id, name: s.name }))

  if (!canUnit && !canService) return null

  const count = selected.length
  const close = () => {
    setDialog(null)
    setTargetId('')
    setDependency('runs_on')
  }

  const apply = async () => {
    const target = options.find((o) => o.id === targetId)
    if (!dialog || !target) return
    setSubmitting(true)
    try {
      const failed = await linkInBatches(selected, (a) =>
        dialog === 'unit'
          ? addAssetToBusinessUnit(target.id, a.id)
          : linkServiceAsset(target.id, a.id, dependency)
      )
      const name = target.name
      if (failed === 0)
        toast.success(
          count === 1
            ? t('assets.bizctx.addedOne', 'Added 1 asset to {name}', { name })
            : t('assets.bizctx.addedMany', 'Added {count} assets to {name}', { count, name })
        )
      else if (failed < count)
        toast.warning(
          t(
            'assets.bizctx.addedPartial',
            'Added {done} of {count} assets to {name}; {failed} failed',
            {
              done: count - failed,
              count,
              name,
              failed,
            }
          )
        )
      else {
        toast.error(
          count === 1
            ? t('assets.bizctx.failedOne', 'Could not add 1 asset to {name}', { name })
            : t('assets.bizctx.failedMany', 'Could not add {count} assets to {name}', {
                count,
                name,
              })
        )
        return
      }
      close()
      onDone()
    } finally {
      setSubmitting(false)
    }
  }

  const isUnit = dialog === 'unit'

  return (
    <>
      {canUnit && (
        <Button variant="ghost" size="sm" onClick={() => setDialog('unit')}>
          <Building2 className="me-2 h-4 w-4" />
          {t('assets.bizctx.addToUnit', 'Add to unit')}
        </Button>
      )}
      {canService && (
        <Button variant="ghost" size="sm" onClick={() => setDialog('service')}>
          <Building className="me-2 h-4 w-4" />
          {t('assets.bizctx.addToService', 'Add to service')}
        </Button>
      )}

      <Dialog open={dialog !== null} onOpenChange={(o) => !o && close()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {isUnit
                ? t('assets.bizctx.titleUnit', 'Add to business unit')
                : t('assets.bizctx.titleService', 'Add to business service')}
            </DialogTitle>
            <DialogDescription>
              {isUnit
                ? count === 1
                  ? t(
                      'assets.bizctx.descUnitOne',
                      'Add 1 selected asset to a business unit. It takes on its criticality when that is higher than its own.'
                    )
                  : t(
                      'assets.bizctx.descUnitMany',
                      'Add {count} selected assets to a business unit. They take on its criticality when that is higher than their own.',
                      { count }
                    )
                : count === 1
                  ? t(
                      'assets.bizctx.descServiceOne',
                      'Link 1 selected asset to a business service. A cycle scoped to the service covers it.'
                    )
                  : t(
                      'assets.bizctx.descServiceMany',
                      'Link {count} selected assets to a business service. A cycle scoped to the service covers them.',
                      { count }
                    )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="bulk-context-target">
                  {isUnit
                    ? t('assets.bizctx.unit', 'Business unit')
                    : t('assets.bizctx.service', 'Business service')}
                </Label>
                <Select value={targetId} onValueChange={setTargetId}>
                  <SelectTrigger id="bulk-context-target" className="w-full">
                    <SelectValue
                      placeholder={
                        isUnit
                          ? t('assets.bizctx.chooseUnit', 'Choose a business unit')
                          : t('assets.bizctx.chooseService', 'Choose a business service')
                      }
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {options.length === 0 ? (
                      <div className="px-2 py-3 text-sm text-muted-foreground">
                        {isUnit
                          ? t(
                              'assets.bizctx.noUnits',
                              'No business units yet. Create one under Scoping › Business context.'
                            )
                          : t(
                              'assets.bizctx.noServices',
                              'No business services yet. Create one under Scoping › Business context.'
                            )}
                      </div>
                    ) : (
                      options.map((o) => (
                        <SelectItem key={o.id} value={o.id}>
                          {o.name}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
              </div>
              {dialog === 'service' && (
                <div className="space-y-2">
                  <Label htmlFor="bulk-context-dependency">
                    {t('assets.bizctx.dependency', 'How the service uses them')}
                  </Label>
                  <Select
                    value={dependency}
                    onValueChange={(v) => setDependency(v as DependencyType)}
                  >
                    <SelectTrigger id="bulk-context-dependency" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {DEPENDENCY_TYPES.map((d) => (
                        <SelectItem key={d.value} value={d.value}>
                          {d.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={close}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={apply} disabled={submitting || !targetId}>
              {submitting
                ? t('assets.bulk.adding', 'Adding…')
                : t('assets.bulk.addSelected', 'Add {count} selected', { count })}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
