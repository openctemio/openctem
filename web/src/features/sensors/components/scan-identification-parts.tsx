'use client'

import { Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import {
  MAX_HEADER_NAME,
  MAX_HEADER_VALUE,
  headerListErrors,
  previewLines,
  type EffectiveIdentity,
  type IdentHeader,
} from '../lib/scan-identification'

/**
 * The editable list of scan identification headers: free name and value per
 * row, with the API's rules checked as the user types. Shared by the
 * organization page and the platform console (which adds the enforced
 * switch).
 */
export function HeaderListEditor({
  idPrefix,
  headers,
  onChange,
  max,
  disabled,
  withEnforced,
}: {
  idPrefix: string
  headers: IdentHeader[]
  onChange: (next: IdentHeader[]) => void
  max: number
  disabled?: boolean
  withEnforced?: boolean
}) {
  const { t } = useTranslation()
  const errors = headerListErrors(headers, t)
  const set = (i: number, patch: Partial<IdentHeader>) =>
    onChange(headers.map((h, j) => (j === i ? { ...h, ...patch } : h)))
  return (
    <div className="space-y-3" data-testid={`${idPrefix}-headers`}>
      {headers.length > 0 && (
        <div className="hidden grid-cols-[1fr_1.5fr_auto] gap-2 text-sm font-medium text-muted-foreground sm:grid">
          <span>{t('sensors.scanIdent.headerName', 'Name')}</span>
          <span>{t('sensors.scanIdent.headerValue', 'Value')}</span>
          <span className="sr-only">{t('sensors.scanIdent.remove', 'Remove header')}</span>
        </div>
      )}
      {headers.map((h, i) => (
        <div key={i} className="space-y-1">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1.5fr_auto] sm:items-center">
            <Input
              id={`${idPrefix}-name-${i}`}
              aria-label={t('sensors.scanIdent.headerNameN', 'Header {n} name', { n: i + 1 })}
              aria-invalid={errors[i] ? true : undefined}
              className="font-mono"
              placeholder="X-Scan-Id"
              value={h.name}
              maxLength={MAX_HEADER_NAME}
              onChange={(e) => set(i, { name: e.target.value })}
              disabled={disabled}
            />
            <Input
              aria-label={t('sensors.scanIdent.headerValueN', 'Header {n} value', { n: i + 1 })}
              aria-invalid={errors[i] ? true : undefined}
              className="font-mono"
              value={h.value}
              maxLength={MAX_HEADER_VALUE}
              onChange={(e) => set(i, { value: e.target.value })}
              disabled={disabled}
            />
            <div className="flex items-center gap-3">
              {withEnforced && (
                <div className="flex items-center gap-2">
                  <Switch
                    id={`${idPrefix}-enforced-${i}`}
                    checked={!!h.enforced}
                    onCheckedChange={(v) => set(i, { enforced: v })}
                    disabled={disabled}
                  />
                  <Label htmlFor={`${idPrefix}-enforced-${i}`} className="text-sm font-normal">
                    {t('sensors.scanIdent.enforced', 'Enforced')}
                  </Label>
                </div>
              )}
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={t('sensors.scanIdent.removeN', 'Remove header {n}', { n: i + 1 })}
                onClick={() => onChange(headers.filter((_, j) => j !== i))}
                disabled={disabled}
              >
                <X className="size-4" />
              </Button>
            </div>
          </div>
          {errors[i] && <p className="text-sm text-destructive">{errors[i]}</p>}
        </div>
      ))}
      <div className="flex items-center justify-between gap-3">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onChange([...headers, { name: '', value: '' }])}
          disabled={disabled || headers.length >= max}
        >
          <Plus className="me-1.5 size-4" />
          {t('sensors.scanIdent.add', 'Add header')}
        </Button>
        <span className="text-sm text-muted-foreground">
          {t('sensors.scanIdent.used', '{n} of {max} used', { n: headers.length, max })}
        </span>
      </div>
    </div>
  )
}

/** The exact request lines a target receives from the merged layers. */
export function IdentityPreview({ identity }: { identity: EffectiveIdentity }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-2" data-testid="scan-ident-preview">
      <pre className="overflow-x-auto rounded-md border bg-muted/40 p-3 font-mono text-sm">
        {previewLines(identity).join('\n')}
      </pre>
      <p className="text-sm text-muted-foreground">
        {t(
          'sensors.scanIdent.previewNote',
          "A sensor's local policy may add headers of its own, and bug-bounty program rules apply on program targets."
        )}
      </p>
    </div>
  )
}
