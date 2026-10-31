'use client'

import { useEffect, useMemo, useState } from 'react'
import { AlertCircle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { createScanZone, invalidateScanZonesCache, updateScanZone } from '@/lib/api/scan-zone-hooks'
import type { ScanZone } from '@/lib/api/scan-zone-types'

import { describeScanZoneError } from '../lib/errors'
import {
  MAX_ZONE_DESCRIPTION_LENGTH,
  MAX_ZONE_NAME_LENGTH,
  parseRanges,
  splitRangeInput,
} from '../lib/ranges'
import { RangeChips } from './range-chips'

interface ScanZoneDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Edit this zone; omit to create one. */
  zone?: ScanZone | null
  /** Another zone is already the default (the API allows one). */
  otherDefaultZone?: ScanZone | null
  onSaved?: (zone: ScanZone) => void
}

interface ServerError {
  message: string
  hint?: string
}

export function ScanZoneDialog({
  open,
  onOpenChange,
  zone,
  otherDefaultZone,
  onSaved,
}: ScanZoneDialogProps) {
  const { t } = useTranslation()
  const editing = !!zone
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [isDefault, setIsDefault] = useState(false)
  const [rangesText, setRangesText] = useState('')
  const [touched, setTouched] = useState(false)
  const [saving, setSaving] = useState(false)
  const [serverError, setServerError] = useState<ServerError | null>(null)

  useEffect(() => {
    if (!open) return
    setName(zone?.name ?? '')
    setDescription(zone?.description ?? '')
    setIsDefault(zone?.is_default ?? false)
    setRangesText((zone?.ranges ?? []).join('\n'))
    setTouched(false)
    setServerError(null)
  }, [open, zone])

  const entries = useMemo(() => splitRangeInput(rangesText), [rangesText])
  const parsed = useMemo(() => parseRanges(entries), [entries])

  const nameError = !name.trim()
    ? t('scans.zones.dialog.err.nameRequired')
    : name.trim().length > MAX_ZONE_NAME_LENGTH
      ? t('scans.zones.dialog.err.nameLong', undefined, { max: MAX_ZONE_NAME_LENGTH })
      : null
  const descriptionError =
    description.trim().length > MAX_ZONE_DESCRIPTION_LENGTH
      ? t('scans.zones.dialog.err.descLong', undefined, { max: MAX_ZONE_DESCRIPTION_LENGTH })
      : null
  const rangesRequiredError =
    !isDefault && entries.length === 0 ? t('scans.zones.dialog.err.rangesRequired') : null
  const hasClientError =
    !!nameError || !!descriptionError || !!rangesRequiredError || parsed.errors.length > 0

  const handleSave = async () => {
    setTouched(true)
    setServerError(null)
    if (hasClientError) return
    setSaving(true)
    try {
      // The server normalises and validates again; it is the authority.
      const body = {
        name: name.trim(),
        description: description.trim(),
        is_default: isDefault,
        ranges: entries,
      }
      const saved = zone ? await updateScanZone(zone.id, body) : await createScanZone(body)
      toast.success(
        editing
          ? t('scans.zones.toast.saved', undefined, { name: saved.name })
          : t('scans.zones.toast.created', undefined, { name: saved.name })
      )
      await invalidateScanZonesCache()
      onSaved?.(saved)
      onOpenChange(false)
    } catch (err) {
      const d = describeScanZoneError(
        err,
        editing ? t('scans.zones.toast.saveFailed') : t('scans.zones.toast.createFailed')
      )
      setServerError({ message: d.message, hint: d.hint })
    } finally {
      setSaving(false)
    }
  }

  const showErrors = touched
  const defaultConflict = isDefault && otherDefaultZone && otherDefaultZone.id !== zone?.id

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {editing ? t('scans.zones.dialog.titleEdit') : t('scans.zones.dialog.titleNew')}
          </DialogTitle>
          <DialogDescription>{t('scans.zones.dialog.desc')}</DialogDescription>
        </DialogHeader>

        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            void handleSave()
          }}
        >
          <DialogBody className="space-y-4">
            {serverError && (
              <Alert variant="destructive" role="alert" data-testid="zone-server-error">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>{serverError.message}</AlertTitle>
                {serverError.hint && <AlertDescription>{serverError.hint}</AlertDescription>}
              </Alert>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="zone-name">{t('scans.zones.dialog.name')}</Label>
              <Input
                id="zone-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('scans.zones.dialog.namePlaceholder')}
                maxLength={MAX_ZONE_NAME_LENGTH + 20}
                aria-invalid={showErrors && !!nameError}
                autoFocus
              />
              {showErrors && nameError && <p className="text-xs text-destructive">{nameError}</p>}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="zone-description">{t('scans.zones.dialog.description')}</Label>
              <Textarea
                id="zone-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                placeholder={t('scans.zones.dialog.optional')}
                aria-invalid={showErrors && !!descriptionError}
              />
              {showErrors && descriptionError && (
                <p className="text-xs text-destructive">{descriptionError}</p>
              )}
            </div>

            <div className="flex items-start justify-between gap-4 rounded-md border p-3">
              <div className="min-w-0 space-y-0.5">
                <Label htmlFor="zone-default">{t('scans.zones.dialog.defaultLabel')}</Label>
                <p className="text-xs text-muted-foreground">
                  {t('scans.zones.dialog.defaultHelp')}
                </p>
                {defaultConflict && (
                  <p className="text-xs text-warning">
                    {t('scans.zones.dialog.defaultConflict', undefined, {
                      name: otherDefaultZone.name,
                    })}
                  </p>
                )}
              </div>
              <Switch id="zone-default" checked={isDefault} onCheckedChange={setIsDefault} />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="zone-ranges">{t('scans.zones.dialog.ranges')}</Label>
              <Textarea
                id="zone-ranges"
                value={rangesText}
                onChange={(e) => setRangesText(e.target.value)}
                rows={5}
                className="font-mono text-sm"
                placeholder={'10.230.0.0/16\n192.168.10.1-192.168.10.200\nfd00:230::/48'}
                aria-invalid={showErrors && (parsed.errors.length > 0 || !!rangesRequiredError)}
                aria-describedby="zone-ranges-help"
              />
              <p id="zone-ranges-help" className="text-xs text-muted-foreground">
                {t('scans.zones.dialog.rangesHelp')}
              </p>
              {parsed.errors.length > 0 && (
                <ul className="space-y-0.5" data-testid="zone-range-errors">
                  {parsed.errors.map((e) => (
                    <li key={`${e.line}-${e.input}`} className="text-xs text-destructive">
                      {e.line > 0
                        ? t('scans.zones.dialog.lineError', undefined, { line: e.line })
                        : ''}
                      {e.message}
                    </li>
                  ))}
                </ul>
              )}
              {showErrors && rangesRequiredError && (
                <p className="text-xs text-destructive">{rangesRequiredError}</p>
              )}
              {parsed.errors.length === 0 && parsed.ranges.length > 0 && (
                <div className="space-y-1 pt-1">
                  <p className="text-xs text-muted-foreground">
                    {parsed.ranges.length === 1
                      ? t('scans.zones.dialog.savedAsOne')
                      : t('scans.zones.dialog.savedAsMany', undefined, {
                          count: parsed.ranges.length,
                        })}
                    {parsed.privateCount > 0
                      ? t('scans.zones.dialog.privateSuffix', undefined, {
                          count: parsed.privateCount,
                        })
                      : ''}
                  </p>
                  <RangeChips ranges={parsed.ranges} max={6} />
                </div>
              )}
            </div>
          </DialogBody>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              {t('scans.zones.dialog.cancel')}
            </Button>
            <Button type="submit" disabled={saving}>
              {saving && <Loader2 className="h-4 w-4 animate-spin" />}
              {editing ? t('scans.zones.dialog.save') : t('scans.zones.dialog.create')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
