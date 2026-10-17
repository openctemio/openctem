'use client'

/**
 * System > Shared sensors: the egress addresses organizations see to
 * allowlist the shared sensors (api docs/rfcs/RFC-100-shared-sensors.md §9).
 * One address or CIDR range per line, for every region and per region. The
 * API accepts public addresses only (private, loopback, link-local, metadata
 * and CGNAT ranges are refused) and returns the list normalized. A change
 * needs a super admin, a reason and a fresh authenticator code; it is audited
 * and the other administrators are emailed.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '../api/admin-client'

export interface SharedSensorsEgressFormProps {
  global: string[]
  regions: Record<string, string[]>
  canEdit: boolean
  onSave: (
    global: string[],
    regions: Record<string, string[]>,
    reason: string,
    code: string
  ) => Promise<void>
}

interface RegionRow {
  key: number
  name: string
  text: string
}

/** One entry per line (commas and spaces also separate). */
export function parseAddresses(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

function rowsFrom(regions: Record<string, string[]>): RegionRow[] {
  return Object.keys(regions)
    .sort()
    .map((name, i) => ({ key: i, name, text: regions[name].join('\n') }))
}

export function SharedSensorsEgressForm({
  global,
  regions,
  canEdit,
  onSave,
}: SharedSensorsEgressFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [globalText, setGlobalText] = useState(global.join('\n'))
  const [rows, setRows] = useState<RegionRow[]>(() => rowsFrom(regions))
  const [nextKey, setNextKey] = useState(() => Object.keys(regions).length)
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => setGlobalText(global.join('\n')), [global])
  useEffect(() => {
    setRows(rowsFrom(regions))
    setNextKey(Object.keys(regions).length)
  }, [regions])

  const names = rows.map((r) => r.name.trim())
  const duplicate = names.some((n, i) => n !== '' && names.indexOf(n) !== i)
  const unnamed = rows.some((r) => r.name.trim() === '' && parseAddresses(r.text).length > 0)

  const build = () => {
    const out: Record<string, string[]> = {}
    for (const r of rows) {
      const name = r.name.trim()
      const list = parseAddresses(r.text)
      if (name && list.length > 0) out[name] = list
    }
    return out
  }

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await onSave(parseAddresses(globalText), build(), reason.trim(), code.trim())
      setOpen(false)
      setReason('')
      setCode('')
      toast.success(t('admin.sharedEgress.saved'))
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setOpen(false)
      toast.error(e instanceof Error ? e.message : t('admin.sharedEgress.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  const disabled = !canEdit || busy

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.sharedEgress.title')}</CardTitle>
          <CardDescription>{t('admin.sharedEgress.desc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor={`${id}-global`}>{t('admin.sharedEgress.globalLabel')}</Label>
            <Textarea
              id={`${id}-global`}
              rows={3}
              className="font-mono text-xs"
              value={globalText}
              onChange={(e) => setGlobalText(e.target.value)}
              placeholder={t('admin.sharedEgress.placeholder')}
              disabled={disabled}
            />
            <p className="text-xs text-muted-foreground">{t('admin.sharedEgress.publicOnly')}</p>
          </div>

          {rows.map((r, i) => (
            <div key={r.key} className="space-y-2 rounded-md border p-3">
              <div className="flex items-end gap-2">
                <div className="min-w-0 flex-1 space-y-1">
                  <Label htmlFor={`${id}-region-${r.key}`}>
                    {t('admin.sharedEgress.regionLabel')}
                  </Label>
                  <Input
                    id={`${id}-region-${r.key}`}
                    value={r.name}
                    maxLength={64}
                    onChange={(e) =>
                      setRows(rows.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))
                    }
                    disabled={disabled}
                  />
                </div>
                {canEdit && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => setRows(rows.filter((_, j) => j !== i))}
                    disabled={busy}
                    aria-label={t('admin.sharedEgress.removeRegion', undefined, {
                      region: r.name || '-',
                    })}
                  >
                    <Trash2 className="size-4" aria-hidden />
                  </Button>
                )}
              </div>
              <Textarea
                aria-label={t('admin.sharedEgress.regionAddresses', undefined, {
                  region: r.name || '-',
                })}
                rows={2}
                className="font-mono text-xs"
                value={r.text}
                onChange={(e) =>
                  setRows(rows.map((x, j) => (j === i ? { ...x, text: e.target.value } : x)))
                }
                placeholder={t('admin.sharedEgress.placeholder')}
                disabled={disabled}
              />
            </div>
          ))}
          {(duplicate || unnamed) && (
            <p className="text-sm text-destructive">
              {t(duplicate ? 'admin.sharedEgress.duplicateRegion' : 'admin.sharedEgress.unnamed')}
            </p>
          )}

          {canEdit ? (
            <div className="flex flex-wrap justify-between gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setRows([...rows, { key: nextKey, name: '', text: '' }])
                  setNextKey(nextKey + 1)
                }}
                disabled={busy}
              >
                <Plus className="me-1.5 size-4" aria-hidden />
                {t('admin.sharedEgress.addRegion')}
              </Button>
              <Button onClick={() => setOpen(true)} disabled={busy || duplicate || unnamed}>
                {t('admin.scanPolicy.save')}
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t('admin.scanPolicy.superOnly')}</p>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={open}
        onOpenChange={(o) => {
          if (!busy) setOpen(o)
        }}
        title={t('admin.sharedEgress.confirmTitle')}
        desc={t('admin.sharedEgress.confirmDesc')}
        disabled={code.trim().length < 6 || !reason.trim()}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.scanPolicy.saving')}
            </>
          ) : (
            t('admin.scanPolicy.confirm')
          )
        }
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={`${id}-reason`}>{t('admin.scanPolicy.reason')}</Label>
            <Textarea
              id={`${id}-reason`}
              rows={2}
              maxLength={1000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-code`}>{t('admin.scanPolicy.code')}</Label>
            <Input
              id={`${id}-code`}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={8}
              aria-invalid={!!codeError}
            />
            {codeError && <p className="text-sm text-destructive">{codeError}</p>}
          </div>
        </div>
      </ConfirmDialog>
    </>
  )
}
