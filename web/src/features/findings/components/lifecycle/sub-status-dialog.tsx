'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import { subStatusDotClass } from '@/lib/sub-status-colors'
import {
  CLOSED_STATUSES,
  SUB_STATUS_CLOSURE_REASONS,
  createSubStatus,
  updateSubStatus,
  type LifecycleSubStatus,
  type LifecycleSubStatusInput,
} from '../../api/use-finding-lifecycles'
import { closureReasonLabel } from '../../lib/closure'
import { LIFECYCLE_KEY_PATTERN, isPlanLimitError, slugKey } from '../../lib/lifecycle'
import type { FindingStatus } from '../../types'

interface SubStatusDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The lane a new sub-status goes into; ignored when editing. */
  status: FindingStatus
  /** The sub-status to edit; absent: a new one. */
  subStatus?: LifecycleSubStatus
  colors: string[]
  /** sort_order for a new entry (after the lane's last one). */
  nextSortOrder: number
  onSaved: (s: LifecycleSubStatus) => void
}

const MAX_NAME = 64
const MAX_DESCRIPTION = 500

/**
 * Add or edit a sub-status. The canonical status and closure reason are
 * chosen once: the API refuses to change them later (a label never changes
 * what a metric counts).
 */
export function SubStatusDialog({
  open,
  onOpenChange,
  status,
  subStatus,
  colors,
  nextSortOrder,
  onSaved,
}: SubStatusDialogProps) {
  const { t } = useTranslation()
  const editing = !!subStatus
  const lane = subStatus?.canonical_status ?? status
  const closed = CLOSED_STATUSES.includes(lane)
  const reasons = SUB_STATUS_CLOSURE_REASONS[lane] ?? []

  const [name, setName] = useState('')
  const [nameVi, setNameVi] = useState('')
  const [key, setKey] = useState('')
  const [keyTouched, setKeyTouched] = useState(false)
  const [description, setDescription] = useState('')
  const [color, setColor] = useState('gray')
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setName(subStatus?.name ?? '')
    setNameVi(subStatus?.labels?.vi ?? '')
    setKey(subStatus?.key ?? '')
    setKeyTouched(false)
    setDescription(subStatus?.description ?? '')
    setColor(subStatus?.color || 'gray')
    setReason(subStatus?.closure_reason ?? '')
    setError(null)
  }, [open, subStatus])

  const effectiveKey = editing ? (subStatus?.key ?? '') : keyTouched ? key : slugKey(name)
  const keyValid = LIFECYCLE_KEY_PATTERN.test(effectiveKey)
  const canSave =
    name.trim().length > 0 &&
    name.trim().length <= MAX_NAME &&
    keyValid &&
    (!closed || editing || reason !== '') &&
    !saving

  const submit = async () => {
    if (!canSave) return
    setSaving(true)
    setError(null)
    const labels: Record<string, string> = { ...(subStatus?.labels ?? {}) }
    if (nameVi.trim()) labels.vi = nameVi.trim()
    else delete labels.vi
    try {
      let saved: LifecycleSubStatus
      if (editing && subStatus) {
        const input: LifecycleSubStatusInput = {
          name: name.trim(),
          labels,
          description: description.trim(),
          color,
        }
        saved = await updateSubStatus(subStatus.id, input)
      } else {
        saved = await createSubStatus({
          key: effectiveKey,
          canonical_status: lane,
          closure_reason: closed ? reason : undefined,
          name: name.trim(),
          labels,
          description: description.trim(),
          color,
          sort_order: nextSortOrder,
        })
      }
      toast.success(t('findingLifecycle.subStatus.saved', 'Sub-status saved'))
      onSaved(saved)
      onOpenChange(false)
    } catch (err) {
      setError(
        isPlanLimitError(err)
          ? t(
              'findingLifecycle.plan.subStatusesReached',
              'This organization has reached its limit of sub-statuses. Archive one, or ask your administrator for more.'
            )
          : getErrorMessage(
              err,
              t('findingLifecycle.subStatus.saveFailed', 'Could not save the sub-status')
            )
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {editing
              ? t('findingLifecycle.subStatus.editTitle', 'Edit sub-status')
              : t('findingLifecycle.subStatus.addTitle', 'Add a sub-status to {status}', {
                  status: t(`findings.status.${lane}`, lane),
                })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'findingLifecycle.subStatus.dialogHint',
              'A label inside one status. Metrics, SLAs and exports keep reading the status itself.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="sub-status-name">{t('findingLifecycle.subStatus.name', 'Name')}</Label>
            <Input
              id="sub-status-name"
              value={name}
              maxLength={MAX_NAME}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('findingLifecycle.subStatus.namePlaceholder', 'In review')}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="sub-status-name-vi">
              {t('findingLifecycle.subStatus.nameVi', 'Name in Vietnamese (optional)')}
            </Label>
            <Input
              id="sub-status-name-vi"
              value={nameVi}
              maxLength={MAX_NAME}
              onChange={(e) => setNameVi(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="sub-status-key">{t('findingLifecycle.subStatus.key', 'Key')}</Label>
            <Input
              id="sub-status-key"
              value={effectiveKey}
              disabled={editing}
              className="font-mono"
              onChange={(e) => {
                setKeyTouched(true)
                setKey(e.target.value)
              }}
              aria-invalid={effectiveKey !== '' && !keyValid}
            />
            <p className="text-xs text-muted-foreground">
              {editing
                ? t('findingLifecycle.subStatus.keyFixed', 'The key never changes.')
                : t(
                    'findingLifecycle.subStatus.keyHint',
                    'Lower-case letters, digits and underscores; used by the API and imports.'
                  )}
            </p>
          </div>
          {closed && (
            <div className="space-y-1.5">
              <Label htmlFor="sub-status-reason">
                {t('findingLifecycle.subStatus.closureReason', 'Closure reason')}
              </Label>
              <Select value={reason} onValueChange={setReason} disabled={editing}>
                <SelectTrigger id="sub-status-reason" className="w-full">
                  <SelectValue
                    placeholder={t('findingLifecycle.subStatus.pickReason', 'Choose a reason')}
                  />
                </SelectTrigger>
                <SelectContent>
                  {reasons.map((r) => (
                    <SelectItem key={r} value={r}>
                      {closureReasonLabel(t, r)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t(
                  'findingLifecycle.subStatus.reasonHint',
                  'A closed sub-status is bound to one closure reason for good.'
                )}
              </p>
            </div>
          )}
          <div className="space-y-1.5">
            <Label htmlFor="sub-status-description">
              {t('findingLifecycle.subStatus.description', 'Description (optional)')}
            </Label>
            <Textarea
              id="sub-status-description"
              value={description}
              maxLength={MAX_DESCRIPTION}
              rows={2}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium">
              {t('findingLifecycle.subStatus.color', 'Colour')}
            </legend>
            <div role="radiogroup" className="flex flex-wrap gap-1.5">
              {colors.map((c) => (
                <button
                  key={c}
                  type="button"
                  role="radio"
                  aria-checked={color === c}
                  aria-label={t(`findingLifecycle.color.${c}`, c)}
                  title={t(`findingLifecycle.color.${c}`, c)}
                  onClick={() => setColor(c)}
                  className={cn(
                    'flex size-7 items-center justify-center rounded-full border',
                    color === c ? 'ring-2 ring-ring ring-offset-1 ring-offset-background' : ''
                  )}
                >
                  <span aria-hidden className={cn('size-3.5 rounded-full', subStatusDotClass(c))} />
                </button>
              ))}
            </div>
          </fieldset>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={!canSave}>
            {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('findingLifecycle.subStatus.save', 'Save sub-status')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
