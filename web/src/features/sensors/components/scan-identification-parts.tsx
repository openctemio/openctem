'use client'

import { CircleAlert, Plus, X } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import {
  MAX_HEADER_NAME,
  MAX_HEADER_VALUE,
  MAX_QUERY_PART,
  MAX_USER_AGENTS,
  headerListErrors,
  parseUserAgentList,
  previewLines,
  queryError,
  userAgentListErrors,
  type EffectiveIdentity,
  type IdentHeader,
  type IdentQuery,
  type IdentSource,
} from '../lib/scan-identification'

/** The label of a layer that set a value. */
export function useIdentSourceLabel() {
  const { t } = useTranslation()
  return (s: IdentSource | 'program' | undefined) =>
    s === 'platform_enforced'
      ? t('sensors.scanIdent.src.platformEnforced', 'Platform, enforced')
      : s === 'platform'
        ? t('sensors.scanIdent.src.platform', 'Platform default')
        : s === 'program'
          ? t('sensors.scanIdent.src.program', 'Program')
          : t('sensors.scanIdent.src.organization', 'Organization')
}

/**
 * The one main control of each scan identification page: every request must
 * carry a header or the query parameter. lockedBy: a higher layer requires
 * it, so this layer cannot turn it off (the switch shows on, read-only).
 */
export function RequireIdentificationSwitch({
  id,
  checked,
  onChange,
  disabled,
  lockedBy,
}: {
  id: string
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
  lockedBy?: string
}) {
  const { t } = useTranslation()
  return (
    <div className="flex items-start justify-between gap-4" data-testid={`${id}-required`}>
      <div className="space-y-1">
        <Label htmlFor={id}>
          {t('sensors.scanIdent.required.label', 'Require identification on every request')}
        </Label>
        <p className="text-sm text-muted-foreground" id={`${id}-desc`}>
          {t(
            'sensors.scanIdent.required.help',
            'Tools that cannot carry the headers or query parameter are skipped with a reason; nothing is sent without them.'
          )}
        </p>
        {lockedBy && (
          <p className="text-sm text-muted-foreground">
            {t('sensors.scanIdent.required.lockedBy', 'Required by: {source}', {
              source: lockedBy,
            })}
          </p>
        )}
      </div>
      <Switch
        id={id}
        aria-describedby={`${id}-desc`}
        checked={checked || !!lockedBy}
        onCheckedChange={onChange}
        disabled={disabled || !!lockedBy}
      />
    </div>
  )
}

/**
 * Required identification with no header and no query parameter in force:
 * the error names the fix and offers it.
 */
export function RequiredMissingAlert({ onAddHeader }: { onAddHeader?: () => void }) {
  const { t } = useTranslation()
  return (
    <Alert variant="destructive" data-testid="scan-ident-required-missing">
      <CircleAlert className="size-4" aria-hidden />
      <AlertDescription className="flex flex-wrap items-center gap-3">
        <span>
          {t(
            'sensors.scanIdent.required.missing',
            'Identification is required, but no header or query parameter is set. Scans would fail until you add one.'
          )}
        </span>
        {onAddHeader && (
          <Button type="button" size="sm" variant="outline" onClick={onAddHeader}>
            <Plus className="me-1.5 size-4" />
            {t('sensors.scanIdent.add', 'Add header')}
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}

/**
 * The User-Agent rotation list: one value per line, live count and per-line
 * errors (the API checks again). Each target host of a run gets one value.
 */
export function UserAgentRotationField({
  id,
  text,
  onChange,
  disabled,
}: {
  id: string
  text: string
  onChange: (text: string) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const count = parseUserAgentList(text).length
  const errors = userAgentListErrors(text, t)
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{t('sensors.scanIdent.rotation.label', 'User-Agent rotation')}</Label>
      <p className="text-sm text-muted-foreground" id={`${id}-desc`}>
        {t(
          'sensors.scanIdent.rotation.help',
          'One User-Agent per line, instead of the single one. Each target host of a run gets one of them, the same for the whole run. Headers and the query parameter are sent with every value.'
        )}
      </p>
      <Textarea
        id={id}
        aria-describedby={`${id}-desc`}
        aria-invalid={errors.length > 0 ? true : undefined}
        className="min-h-28 font-mono"
        value={text}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        spellCheck={false}
      />
      <div className="flex flex-wrap justify-between gap-2 text-sm">
        <ul className="space-y-0.5 text-destructive">
          {errors.slice(0, 5).map((e) => (
            <li key={`${e.line}-${e.message}`}>
              {e.line > 0
                ? t('sensors.scanIdent.rotation.lineError', 'Line {line}: {message}', {
                    line: e.line,
                    message: e.message,
                  })
                : e.message}
            </li>
          ))}
        </ul>
        <span className="text-muted-foreground" data-testid={`${id}-count`}>
          {t('sensors.scanIdent.used', '{n} of {max} used', { n: count, max: MAX_USER_AGENTS })}
        </span>
      </div>
    </div>
  )
}

/** The identification query parameter: a name and a URL-safe value. */
export function QueryParamFields({
  idPrefix,
  value,
  onChange,
  disabled,
}: {
  idPrefix: string
  value: IdentQuery
  onChange: (q: IdentQuery) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const err = queryError(value, t)
  return (
    <div className="space-y-2">
      <Label htmlFor={`${idPrefix}-query-name`}>
        {t('sensors.scanIdent.query.label', 'Query parameter')}
      </Label>
      <p className="text-sm text-muted-foreground">
        {t(
          'sensors.scanIdent.query.help',
          'Added to the URL of every request, for example ?scan=corp-1. Letters, digits and . _ ~ - only. Leave both empty for none.'
        )}
      </p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <Input
          id={`${idPrefix}-query-name`}
          aria-label={t('sensors.scanIdent.query.name', 'Parameter name')}
          aria-invalid={err ? true : undefined}
          className="font-mono"
          placeholder="scan"
          value={value.name}
          maxLength={MAX_QUERY_PART}
          onChange={(e) => onChange({ ...value, name: e.target.value })}
          disabled={disabled}
        />
        <Input
          aria-label={t('sensors.scanIdent.query.value', 'Parameter value')}
          aria-invalid={err ? true : undefined}
          className="font-mono"
          placeholder="corp-1"
          value={value.value}
          maxLength={MAX_QUERY_PART}
          onChange={(e) => onChange({ ...value, value: e.target.value })}
          disabled={disabled}
        />
      </div>
      {err && <p className="text-sm text-destructive">{err}</p>}
    </div>
  )
}

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
      {identity.userAgents.length > 1 && (
        <p className="text-sm text-muted-foreground">
          {t(
            'sensors.scanIdent.rotatingOver',
            'The User-Agent rotates over {n} values: each target host gets one per run.',
            { n: identity.userAgents.length }
          )}
        </p>
      )}
      <p className="text-sm text-muted-foreground">
        {t(
          'sensors.scanIdent.previewNote',
          "A sensor's local policy may add headers of its own, and bug-bounty program rules apply on program targets."
        )}
      </p>
    </div>
  )
}
