'use client'

/**
 * Settings → Scanning → Sensor products: the organization records the latest
 * and minimum release of sensors it builds itself on sdk-go, so they show
 * "update available" and "unsupported" (api
 * docs/architecture/sensor-compatibility.md). First-party products are managed
 * by the platform. The API validates every value; the form only hints.
 */

import { useMemo, useState, type FormEvent } from 'react'
import { Info, Loader2, Lock, Package, Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, PageHeader } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  deleteCustomProduct,
  saveCustomProduct,
  useCustomProducts,
  type CustomProduct,
} from '@/lib/api/sensor-custom-products-hooks'
import { useAllSensors } from '@/lib/api/sensor-hooks'
import { Can, Permission, useHasPermission } from '@/lib/permissions'

import { exactTime } from '../lib/format'
import { sensorProductId } from '../lib/sensor-version'

const VERSION_SHAPE = /^v?\d+\.\d+\.\d+$/

/** A version field is fine empty ("not set") or shaped vX.Y.Z / X.Y.Z. */
export const versionShapeOk = (v: string) => v.trim() === '' || VERSION_SHAPE.test(v.trim())

interface Editing {
  product: string
  latest: string
  min: string
  isNew: boolean
}

function ProductDialog({
  editing,
  onClose,
  onSaved,
}: {
  editing: Editing | null
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  // The dialog is remounted per target (key), so state starts from the target.
  const [product, setProduct] = useState(editing?.product ?? '')
  const [latest, setLatest] = useState(editing?.latest ?? '')
  const [min, setMin] = useState(editing?.min ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!editing || busy) return
    setBusy(true)
    setError(null)
    try {
      await saveCustomProduct(product.trim(), {
        latest_version: latest.trim(),
        min_version: min.trim(),
      })
      toast.success(t('sensors.customProducts.saved'))
      onSaved()
      onClose()
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const hint = (v: string) =>
    versionShapeOk(v) ? null : (
      <p className="text-xs text-warning">{t('sensors.customProducts.versionHint')}</p>
    )

  return (
    <Dialog open={editing !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="md">
        <DialogForm onSubmit={submit} noValidate>
          <DialogHeader>
            <DialogTitle>
              {editing?.isNew
                ? t('sensors.customProducts.addTitle')
                : t('sensors.customProducts.editTitle')}
            </DialogTitle>
            <DialogDescription>{t('sensors.customProducts.dialogDescription')}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <div className="space-y-2">
              <Label htmlFor="custom-product-name">{t('sensors.customProducts.product')}</Label>
              <Input
                id="custom-product-name"
                value={product}
                disabled={!editing?.isNew}
                onChange={(e) => setProduct(e.target.value)}
                placeholder={t('sensors.customProducts.productPlaceholder')}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="custom-product-latest">{t('sensors.customProducts.latest')}</Label>
                <Input
                  id="custom-product-latest"
                  value={latest}
                  onChange={(e) => setLatest(e.target.value)}
                  placeholder="v1.4.0"
                  autoComplete="off"
                  spellCheck={false}
                />
                {hint(latest)}
              </div>
              <div className="space-y-2">
                <Label htmlFor="custom-product-min">{t('sensors.customProducts.min')}</Label>
                <Input
                  id="custom-product-min"
                  value={min}
                  onChange={(e) => setMin(e.target.value)}
                  placeholder="v1.2.0"
                  autoComplete="off"
                  spellCheck={false}
                />
                {hint(min)}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">{t('sensors.customProducts.emptyNote')}</p>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy || product.trim() === ''}>
              {busy && <Loader2 className="size-4 animate-spin" aria-hidden="true" />}
              {t('common.save')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

export function SensorProductsSettings() {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const { data, error, isLoading, mutate } = useCustomProducts()
  const sensors = useAllSensors(undefined, canWrite)
  const [editing, setEditing] = useState<Editing | null>(null)
  const [removing, setRemoving] = useState<CustomProduct | null>(null)
  const [busy, setBusy] = useState(false)

  const items = data?.items
  // Products the organization's sensors report that the platform does not
  // know and that are not recorded yet.
  const suggestions = useMemo(() => {
    const recorded = new Set((items ?? []).map((i) => i.product))
    const out = new Set<string>()
    for (const s of sensors.data?.items ?? []) {
      if (s.product_known !== false) continue
      const id = sensorProductId(s)
      if (id && !recorded.has(id)) out.add(id)
    }
    return [...out].sort()
  }, [items, sensors.data])

  const confirmRemove = async () => {
    if (!removing) return
    setBusy(true)
    try {
      await deleteCustomProduct(removing.product)
      toast.success(t('sensors.customProducts.removed'))
      setRemoving(null)
      void mutate()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const notSet = t('sensors.customProducts.notSet')

  return (
    <>
      <PageHeader
        title={t('sensors.customProducts.title')}
        description={t('sensors.customProducts.description')}
      >
        <Can permission={Permission.SensorsWrite}>
          <Button onClick={() => setEditing({ product: '', latest: '', min: '', isNew: true })}>
            <Plus className="size-4" aria-hidden="true" />
            {t('sensors.customProducts.add')}
          </Button>
        </Can>
      </PageHeader>
      <div className="mt-5 space-y-4">
        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>{t('sensors.customProducts.note')}</AlertDescription>
        </Alert>
        {!canWrite && (
          <p className="inline-flex items-center gap-1 text-sm text-muted-foreground">
            <Lock className="h-3.5 w-3.5" aria-hidden />
            {t('sensors.customProducts.readOnly')}
          </p>
        )}
        {canWrite && suggestions.length > 0 && (
          <div className="space-y-2" data-testid="custom-product-suggestions">
            <p className="text-sm text-muted-foreground">{t('sensors.customProducts.suggest')}</p>
            <div className="flex flex-wrap gap-2">
              {suggestions.map((p) => (
                <Button
                  key={p}
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setEditing({ product: p, latest: '', min: '', isNew: true })}
                >
                  <Plus className="size-3.5" aria-hidden="true" />
                  {p}
                </Button>
              ))}
            </div>
          </div>
        )}
        {isLoading && <Skeleton className="h-40 w-full" />}
        {error && !isLoading && (
          <ErrorState
            title={t('sensors.customProducts.loadError')}
            error={error}
            onRetry={() => void mutate()}
          />
        )}
        {!isLoading && !error && items?.length === 0 && (
          <EmptyState
            icon={Package}
            title={t('sensors.customProducts.emptyTitle')}
            description={t('sensors.customProducts.empty')}
          />
        )}
        {items && items.length > 0 && (
          <div className="overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('sensors.customProducts.product')}</TableHead>
                  <TableHead>{t('sensors.customProducts.latest')}</TableHead>
                  <TableHead>{t('sensors.customProducts.min')}</TableHead>
                  <TableHead className="hidden sm:table-cell">
                    {t('sensors.customProducts.updated')}
                  </TableHead>
                  {canWrite && (
                    <TableHead className="w-24">
                      <span className="sr-only">{t('sensors.customProducts.actions')}</span>
                    </TableHead>
                  )}
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((i) => (
                  <TableRow key={i.product} data-testid={`custom-product-${i.product}`}>
                    <TableCell className="font-mono text-sm">{i.product}</TableCell>
                    <TableCell className="tabular-nums">{i.latest_version || notSet}</TableCell>
                    <TableCell className="tabular-nums">{i.min_version || notSet}</TableCell>
                    <TableCell className="hidden text-muted-foreground sm:table-cell">
                      {exactTime(i.updated_at) ?? ''}
                    </TableCell>
                    {canWrite && (
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            aria-label={t('sensors.customProducts.edit', undefined, {
                              product: i.product,
                            })}
                            onClick={() =>
                              setEditing({
                                product: i.product,
                                latest: i.latest_version,
                                min: i.min_version,
                                isNew: false,
                              })
                            }
                          >
                            <Pencil className="size-4" aria-hidden="true" />
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            aria-label={t('sensors.customProducts.delete', undefined, {
                              product: i.product,
                            })}
                            onClick={() => setRemoving(i)}
                          >
                            <Trash2 className="size-4" aria-hidden="true" />
                          </Button>
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
      {editing && (
        <ProductDialog
          key={`${editing.isNew}:${editing.product}`}
          editing={editing}
          onClose={() => setEditing(null)}
          onSaved={() => void mutate()}
        />
      )}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t('sensors.customProducts.deleteTitle')}
        desc={t('sensors.customProducts.deleteDescription', undefined, {
          product: removing?.product ?? '',
        })}
        confirmText={t('sensors.customProducts.deleteConfirm')}
        destructive
        isLoading={busy}
        handleConfirm={confirmRemove}
      />
    </>
  )
}
