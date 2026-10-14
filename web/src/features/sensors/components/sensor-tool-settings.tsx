'use client'

import { useMemo, useState } from 'react'
import { AlertTriangle, SlidersHorizontal } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  resetSensorToolSettings,
  saveSensorToolSettings,
  toolSettingsProblems,
  useSensorEffectiveToolSettings,
  useSensorToolSettings,
  type SensorToolSettings,
} from '@/lib/api/sensor-tool-settings-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'

import {
  defaultText,
  draftFromValues,
  problemKey,
  toolSettingFields,
  valuesFromDraft,
  type Draft,
  type DraftValue,
  type ToolSettingField,
} from '../lib/tool-settings'

type T = ReturnType<typeof useTranslation>['t']

const SELECT_CLASS =
  'h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm shadow-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50'

function fieldLabel(f: ToolSettingField, tool: string, t: T): string {
  // Built-in tools and the common options have translated titles; a
  // third-party tool's title shows as reported (text).
  if (f.common) return t(`sensors.toolOptions.common.${f.common}`, f.title ?? f.key)
  return t(`sensors.toolOptions.tool.${tool}.${f.key}`, f.title ?? f.key)
}

function FieldTags({ f, t }: { f: ToolSettingField; t: T }) {
  return (
    <span className="flex flex-wrap items-center gap-1">
      {f.flag && (
        <Badge variant="outline" className="font-mono text-[10px]">
          {f.flag}
        </Badge>
      )}
      {f.tier === 'T1' && (
        <Badge variant="secondary" className="text-[10px]">
          {t('sensors.toolOptions.safety.impact')}
        </Badge>
      )}
      {f.tier === 'T2' && (
        <Badge variant="destructive" className="text-[10px]">
          {t('sensors.toolOptions.safety.dangerous')}
        </Badge>
      )}
      {f.scope === 'scan' && (
        <Badge variant="outline" className="text-[10px]">
          {t('sensors.toolSettings.scanOverridable')}
        </Badge>
      )}
    </span>
  )
}

function FieldInput({
  id,
  f,
  value,
  disabled,
  onChange,
  t,
}: {
  id: string
  f: ToolSettingField
  value: DraftValue
  disabled: boolean
  onChange: (v: DraftValue) => void
  t: T
}) {
  const placeholder = defaultText(f)
  switch (f.kind) {
    case 'boolean': {
      const checked = typeof value === 'boolean' ? value : f.defaultValue === true
      return (
        <Switch
          id={id}
          checked={checked}
          disabled={disabled}
          onCheckedChange={(c) =>
            onChange(f.defaultValue !== undefined && c === f.defaultValue ? undefined : c)
          }
        />
      )
    }
    case 'integer':
    case 'number':
      return (
        <Input
          id={id}
          type="number"
          inputMode={f.kind === 'integer' ? 'numeric' : 'decimal'}
          step={f.kind === 'integer' ? 1 : 'any'}
          min={f.minimum}
          max={f.maximum}
          placeholder={placeholder}
          value={typeof value === 'string' ? value : ''}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)}
        />
      )
    case 'enum':
      return (
        <select
          id={id}
          className={SELECT_CLASS}
          value={typeof value === 'string' ? value : ''}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)}
        >
          <option value="">
            {placeholder
              ? t('sensors.toolSettings.defaultOption', undefined, { value: placeholder })
              : t('sensors.toolSettings.unset')}
          </option>
          {(f.values ?? []).map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      )
    case 'multi': {
      const selected = Array.isArray(value) ? value : []
      return (
        <div id={id} className="flex flex-wrap gap-x-4 gap-y-2" role="group">
          {(f.values ?? []).map((v) => {
            const cid = `${id}-${v}`
            return (
              <label key={v} htmlFor={cid} className="flex items-center gap-1.5 text-sm">
                <Checkbox
                  id={cid}
                  checked={selected.includes(v)}
                  disabled={disabled}
                  onCheckedChange={(c) => {
                    const next = c ? [...selected, v] : selected.filter((x) => x !== v)
                    onChange(next.length > 0 ? next : undefined)
                  }}
                />
                {v}
              </label>
            )
          })}
        </div>
      )
    }
    case 'list':
      return (
        <Input
          id={id}
          placeholder={placeholder}
          value={Array.isArray(value) ? value.join(', ') : ''}
          disabled={disabled}
          onChange={(e) => {
            const parts = e.target.value
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
            onChange(parts.length > 0 ? parts : undefined)
          }}
        />
      )
    default:
      return (
        <Input
          id={id}
          placeholder={placeholder}
          value={typeof value === 'string' ? value : ''}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)}
        />
      )
  }
}

function EffectiveTable({ sensorId, tool, t }: { sensorId: string; tool: string; t: T }) {
  const { data, error, isLoading } = useSensorEffectiveToolSettings(sensorId, tool)
  if (isLoading) return <Skeleton className="h-16 w-full" />
  if (error || !data) {
    return (
      <p className="text-sm text-destructive">
        {getErrorMessage(error, t('sensors.toolSettings.effectiveError'))}
      </p>
    )
  }
  return (
    <div
      className="overflow-x-auto rounded-md border"
      data-testid={`tool-settings-effective-${tool}`}
    >
      <table className="w-full text-xs">
        <thead className="bg-muted/40 text-left text-muted-foreground">
          <tr>
            <th className="px-2 py-1 font-medium">{t('sensors.toolSettings.effective.key')}</th>
            <th className="px-2 py-1 font-medium">{t('sensors.toolSettings.effective.value')}</th>
            <th className="px-2 py-1 font-medium">{t('sensors.toolSettings.effective.source')}</th>
            <th className="px-2 py-1 font-medium">{t('sensors.toolSettings.effective.flag')}</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map((e) => (
            <tr key={e.key} className="border-t">
              <td className="px-2 py-1 font-mono">{e.key}</td>
              <td className="px-2 py-1 font-mono">
                {e.value === null || e.value === undefined
                  ? t('sensors.toolSettings.unset')
                  : Array.isArray(e.value)
                    ? e.value.map(String).join(', ')
                    : String(e.value)}
              </td>
              <td className="px-2 py-1">
                {e.source === 'sensor'
                  ? t('sensors.toolSettings.source.sensor')
                  : e.source === 'default'
                    ? t('sensors.toolSettings.source.default')
                    : t('sensors.toolSettings.unset')}
              </td>
              <td className="px-2 py-1 font-mono">{e.flag ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** One tool's settings form. */
export function ToolSettingsForm({
  sensorId,
  item,
  onChanged,
}: {
  sensorId: string
  item: SensorToolSettings
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const fields = useMemo(() => toolSettingFields(item.schema), [item.schema])
  const [draft, setDraft] = useState<Draft>(() => draftFromValues(fields, item.values))
  const [problems, setProblems] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
  const [showEffective, setShowEffective] = useState(false)

  const groups = useMemo(() => {
    const out: { name: string; common: boolean; fields: ToolSettingField[] }[] = []
    for (const f of fields) {
      const name = f.common ? '' : (f.group ?? '')
      const last = out[out.length - 1]
      if (last && last.name === name && last.common === !!f.common) last.fields.push(f)
      else out.push({ name, common: !!f.common, fields: [f] })
    }
    return out
  }, [fields])

  const save = async () => {
    setBusy(true)
    setProblems({})
    try {
      await saveSensorToolSettings(sensorId, item.tool, valuesFromDraft(fields, draft))
      toast.success(t('sensors.toolSettings.saved', undefined, { tool: item.tool }))
      onChanged()
    } catch (err) {
      const list = toolSettingsProblems(err)
      if (list.length > 0) {
        setProblems(Object.fromEntries(list.map((p) => [problemKey(p.path), p.message])))
      }
      toast.error(getErrorMessage(err, t('sensors.toolSettings.saveError')))
    } finally {
      setBusy(false)
    }
  }

  const reset = async () => {
    setBusy(true)
    setProblems({})
    try {
      await resetSensorToolSettings(sensorId, item.tool)
      setDraft({})
      toast.success(t('sensors.toolSettings.resetDone', undefined, { tool: item.tool }))
      onChanged()
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.toolSettings.resetError')))
    } finally {
      setBusy(false)
    }
  }

  const formProblem = problems['']

  return (
    <div className="space-y-3 rounded-md border p-3" data-testid={`tool-settings-${item.tool}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-sm font-medium">{item.tool}</span>
        {item.stored ? (
          <Badge variant="secondary" className="text-xs">
            {t('sensors.toolSettings.customized')}
          </Badge>
        ) : (
          <span className="text-xs text-muted-foreground">
            {t('sensors.toolSettings.allDefaults')}
          </span>
        )}
      </div>

      {item.problems.length > 0 && (
        <div
          className="flex gap-2 rounded-md bg-destructive/10 p-2 text-xs text-destructive"
          role="alert"
        >
          <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden />
          <div className="space-y-1">
            <p>{t('sensors.toolSettings.staleWarning')}</p>
            <ul className="list-disc pl-4">
              {item.problems.map((p) => (
                <li key={p.path}>
                  <span className="font-mono">{problemKey(p.path) || item.tool}</span>: {p.message}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {fields.length === 0 && (
        <p className="text-sm text-muted-foreground">{t('sensors.toolSettings.noFields')}</p>
      )}

      {groups.map((g) => (
        <fieldset key={`${g.common}-${g.name}`} className="space-y-3">
          <legend className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {g.common
              ? t('sensors.toolSettings.commonGroup')
              : g.name || t('sensors.toolSettings.toolGroup')}
          </legend>
          {g.fields.map((f) => {
            const id = `tool-setting-${item.tool}-${f.key}`
            const locked = f.tier === 'T2'
            const problem = problems[f.key]
            return (
              <div key={f.key} className="space-y-1" data-testid={`tool-setting-${f.key}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <Label htmlFor={id}>{fieldLabel(f, item.tool, t)}</Label>
                  <FieldTags f={f} t={t} />
                </div>
                <FieldInput
                  id={id}
                  f={f}
                  value={draft[f.key]}
                  disabled={busy || locked}
                  onChange={(v) => setDraft((d) => ({ ...d, [f.key]: v }))}
                  t={t}
                />
                {f.description && <p className="text-xs text-muted-foreground">{f.description}</p>}
                {(f.minimum !== undefined || f.maximum !== undefined) && (
                  <p className="text-xs text-muted-foreground tabular-nums">
                    {t('sensors.toolSettings.range', undefined, {
                      min: f.minimum ?? '-',
                      max: f.maximum ?? '-',
                    })}
                  </p>
                )}
                {locked && (
                  <p className="text-xs text-muted-foreground">
                    {t('sensors.toolSettings.t2Locked')}
                  </p>
                )}
                {problem && (
                  <p className="text-xs text-destructive" role="alert">
                    {problem}
                  </p>
                )}
              </div>
            )
          })}
        </fieldset>
      ))}

      {formProblem && (
        <p className="text-xs text-destructive" role="alert">
          {formProblem}
        </p>
      )}

      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => void save()} disabled={busy || fields.length === 0}>
          {t('sensors.toolSettings.save')}
        </Button>
        {item.stored && (
          <Button size="sm" variant="outline" onClick={() => void reset()} disabled={busy}>
            {t('sensors.toolSettings.reset')}
          </Button>
        )}
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setShowEffective((s) => !s)}
          aria-expanded={showEffective}
        >
          {showEffective
            ? t('sensors.toolSettings.hideEffective')
            : t('sensors.toolSettings.showEffective')}
        </Button>
      </div>

      {showEffective && <EffectiveTable sensorId={sensorId} tool={item.tool} t={t} />}
    </div>
  )
}

/**
 * The sensor's tool settings, for owners and administrators (sensors:write):
 * a form per tool of the current manifest that declares settings.
 */
export function SensorToolSettingsSection({ sensorId }: { sensorId: string }) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const { data, error, isLoading, mutate } = useSensorToolSettings(sensorId, canWrite)
  if (!canWrite) return null
  const items = data?.items ?? []
  return (
    <DetailSection title={t('sensors.toolSettings.title')} icon={SlidersHorizontal}>
      <p className="text-sm text-muted-foreground">{t('sensors.toolSettings.intro')}</p>
      {isLoading && <Skeleton className="h-24 w-full" />}
      {error && !isLoading && (
        <p className="text-sm text-destructive">
          {getErrorMessage(error, t('sensors.toolSettings.loadError'))}
        </p>
      )}
      {!isLoading && !error && items.length === 0 && (
        <p className="text-sm text-muted-foreground">{t('sensors.toolSettings.empty')}</p>
      )}
      <div className={cn('space-y-3', items.length === 0 && 'hidden')}>
        {items.map((item) => (
          <ToolSettingsForm
            key={`${item.tool}-${item.schema_digest}-${item.updated_at ?? ''}`}
            sensorId={sensorId}
            item={item}
            onChanged={() => void mutate()}
          />
        ))}
      </div>
    </DetailSection>
  )
}
