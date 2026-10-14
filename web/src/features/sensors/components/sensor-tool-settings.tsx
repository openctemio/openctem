'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, RotateCcw, Search, SlidersHorizontal } from 'lucide-react'
import { toast } from 'sonner'

import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion'
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
import { useSensorManifests } from '@/lib/api/sensor-hooks'
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
  changeSummaryList,
  changedFields,
  defaultText,
  draftFromValues,
  fieldMatches,
  isChangedValue,
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

/** Bound on the remembered open tools (the value comes from browser storage). */
const MAX_REMEMBERED = 64

const storageKey = (sensorId: string) => `openctem.sensors.toolSettings.open.${sensorId}`

/** The tools open on this sensor last time; [] when storage is unavailable. */
function readOpenTools(sensorId: string): string[] {
  try {
    const raw = window.localStorage.getItem(storageKey(sensorId))
    const parsed: unknown = raw ? JSON.parse(raw) : []
    if (!Array.isArray(parsed)) return []
    return parsed.filter((v): v is string => typeof v === 'string').slice(0, MAX_REMEMBERED)
  } catch {
    return []
  }
}

function writeOpenTools(sensorId: string, tools: string[]) {
  try {
    window.localStorage.setItem(
      storageKey(sensorId),
      JSON.stringify(tools.slice(0, MAX_REMEMBERED))
    )
  } catch {
    // Storage is a convenience: the list works without it.
  }
}

function isPhoneWidth(): boolean {
  try {
    return (
      typeof window.matchMedia === 'function' && window.matchMedia('(max-width: 639px)').matches
    )
  } catch {
    return false
  }
}

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

interface FieldGroup {
  id: string
  name: string
  common: boolean
  fields: ToolSettingField[]
}

function groupFields(fields: ToolSettingField[]): FieldGroup[] {
  const out: FieldGroup[] = []
  for (const f of fields) {
    const name = f.common ? '' : (f.group ?? '')
    const last = out[out.length - 1]
    if (last && last.name === name && last.common === !!f.common) last.fields.push(f)
    else
      out.push({ id: f.common ? 'common' : `group:${name}`, name, common: !!f.common, fields: [f] })
  }
  return out
}

/** The common options are open; with none, the first group is. */
function initialGroups(groups: FieldGroup[]): string[] {
  const first = groups.find((g) => g.common) ?? groups[0]
  return first ? [first.id] : []
}

/** One tool of the list: its saved state, sorted and matched by the list. */
interface ToolRow {
  item: SensorToolSettings
  fields: ToolSettingField[]
  saved: Draft
  /** Saved values that differ from their defaults (or stale values to fix). */
  attention: boolean
}

function ToolSummary({ fields, draft, t }: { fields: ToolSettingField[]; draft: Draft; t: T }) {
  const changed = changedFields(fields, draft)
  if (changed.length === 0) return <>{t('sensors.toolSettings.allDefaults')}</>
  return (
    <>
      {t('sensors.toolSettings.summaryChanged', undefined, {
        count: changed.length,
        list: changeSummaryList(changed, draft),
      })}
    </>
  )
}

/**
 * One tool of the list: a collapsed row with its summary that opens to its
 * options and, with unsaved changes, one save bar for the tool.
 */
function ToolSettingsItem({
  sensorId,
  row,
  version,
  open,
  matches,
  query,
  hidden,
  onChanged,
}: {
  sensorId: string
  row: ToolRow
  version?: string
  open: boolean
  /** Filtered out by the search: kept mounted so unsaved changes survive. */
  hidden: boolean
  /** Keys of the options that match the search. */
  matches: ReadonlySet<string>
  query: string
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const { item, fields, saved } = row
  const [draft, setDraft] = useState<Draft>(saved)
  const [problems, setProblems] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
  const [showEffective, setShowEffective] = useState(false)
  const groups = useMemo(() => groupFields(fields), [fields])
  const [openGroups, setOpenGroups] = useState<string[]>(() => initialGroups(groups))

  // A new search opens the groups that hold a matching option (state
  // adjusted while rendering, when the query changes).
  const [seenQuery, setSeenQuery] = useState(query)
  if (query !== seenQuery) {
    setSeenQuery(query)
    const hit = groups.filter((g) => g.fields.some((f) => matches.has(f.key))).map((g) => g.id)
    if (hit.some((id) => !openGroups.includes(id))) {
      setOpenGroups([...openGroups, ...hit.filter((id) => !openGroups.includes(id))])
    }
  }

  const dirty = useMemo(
    () =>
      JSON.stringify(valuesFromDraft(fields, draft)) !==
      JSON.stringify(valuesFromDraft(fields, saved)),
    [fields, draft, saved]
  )
  // Stored values that no longer fit the tool are saved again (or reset)
  // even when the form shows no change.
  const needsSave = dirty || item.problems.length > 0
  const anyChanged = changedFields(fields, draft).length > 0

  const save = async () => {
    setBusy(true)
    setProblems({})
    const values = valuesFromDraft(fields, draft)
    try {
      if (Object.keys(values).length === 0 && item.stored) {
        // Every option back at its default: drop the stored settings.
        await resetSensorToolSettings(sensorId, item.tool)
        toast.success(t('sensors.toolSettings.resetDone', undefined, { tool: item.tool }))
      } else {
        await saveSensorToolSettings(sensorId, item.tool, values)
        toast.success(t('sensors.toolSettings.saved', undefined, { tool: item.tool }))
      }
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

  const discard = () => {
    setDraft(saved)
    setProblems({})
  }

  const formProblem = problems['']

  return (
    <AccordionItem
      value={item.tool}
      data-tool={item.tool}
      data-testid={`tool-settings-${item.tool}`}
      hidden={hidden}
      className="flex flex-col max-sm:data-[state=open]:min-h-[calc(100dvh-8rem)]"
    >
      <AccordionTrigger className="min-w-0 items-center px-3 py-2.5 hover:no-underline">
        <span className="flex min-w-0 flex-1 flex-col gap-0.5">
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-mono text-sm font-medium">{item.tool}</span>
            {version && (
              <span className="text-xs font-normal text-muted-foreground tabular-nums">
                {version}
              </span>
            )}
            {item.problems.length > 0 && (
              <Badge variant="destructive" className="text-[10px]">
                {t('sensors.toolSettings.needsAttention')}
              </Badge>
            )}
            {dirty && (
              <Badge variant="outline" className="border-warning/50 text-[10px] text-warning">
                {t('sensors.toolSettings.unsaved')}
              </Badge>
            )}
          </span>
          <span
            className="truncate text-xs font-normal text-muted-foreground"
            data-testid={`tool-settings-summary-${item.tool}`}
          >
            <ToolSummary fields={fields} draft={draft} t={t} />
          </span>
        </span>
      </AccordionTrigger>
      <AccordionContent className="space-y-3 px-3">
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
                    <span className="font-mono">{problemKey(p.path) || item.tool}</span>:{' '}
                    {p.message}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {fields.length === 0 && (
          <p className="text-sm text-muted-foreground">{t('sensors.toolSettings.noFields')}</p>
        )}

        {groups.length > 0 && (
          <Accordion
            type="multiple"
            value={openGroups}
            onValueChange={setOpenGroups}
            className="rounded-md border"
          >
            {groups.map((g) => {
              const changedCount = g.fields.filter((f) => isChangedValue(f, draft[f.key])).length
              return (
                <AccordionItem key={g.id} value={g.id} data-testid={`tool-settings-group-${g.id}`}>
                  <AccordionTrigger className="items-center px-3 py-2 hover:no-underline">
                    <span className="flex flex-1 items-center gap-2">
                      <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                        {g.common
                          ? t('sensors.toolSettings.commonGroup')
                          : g.name || t('sensors.toolSettings.toolGroup')}
                      </span>
                      {changedCount > 0 && (
                        <Badge variant="secondary" className="text-[10px] font-normal">
                          {t('sensors.toolSettings.groupChanged', undefined, {
                            count: changedCount,
                          })}
                        </Badge>
                      )}
                    </span>
                  </AccordionTrigger>
                  <AccordionContent className="space-y-4 px-3">
                    {g.fields.map((f) => {
                      const id = `tool-setting-${item.tool}-${f.key}`
                      const locked = f.tier === 'T2'
                      const problem = problems[f.key]
                      const changed = isChangedValue(f, draft[f.key])
                      const label = fieldLabel(f, item.tool, t)
                      const match = matches.has(f.key)
                      return (
                        <div
                          key={f.key}
                          className={cn(
                            'space-y-1 rounded-md',
                            match &&
                              '-mx-2 bg-primary/5 px-2 py-1.5 ring-1 ring-primary/40 ring-inset'
                          )}
                          data-testid={`tool-setting-${f.key}`}
                          data-search-match={match ? 'true' : undefined}
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            {changed && (
                              <span
                                className="h-2 w-2 shrink-0 rounded-full bg-primary"
                                data-testid={`tool-setting-changed-${f.key}`}
                                title={t('sensors.toolSettings.changedFromDefault')}
                              >
                                <span className="sr-only">
                                  {t('sensors.toolSettings.changedFromDefault')}
                                </span>
                              </span>
                            )}
                            <Label htmlFor={id}>{label}</Label>
                            <FieldTags f={f} t={t} />
                            {changed && !locked && (
                              <Button
                                type="button"
                                size="sm"
                                variant="ghost"
                                className="ms-auto h-7 px-2 text-xs"
                                disabled={busy}
                                aria-label={t('sensors.toolSettings.resetOptionLabel', undefined, {
                                  option: label,
                                })}
                                onClick={() => setDraft((d) => ({ ...d, [f.key]: undefined }))}
                              >
                                <RotateCcw className="h-3.5 w-3.5" aria-hidden />
                                <span className="max-sm:sr-only">
                                  {t('sensors.toolSettings.resetOption')}
                                </span>
                              </Button>
                            )}
                          </div>
                          <FieldInput
                            id={id}
                            f={f}
                            value={draft[f.key]}
                            disabled={busy || locked}
                            onChange={(v) => setDraft((d) => ({ ...d, [f.key]: v }))}
                            t={t}
                          />
                          {f.description && (
                            <p className="text-xs text-muted-foreground">{f.description}</p>
                          )}
                          {(f.minimum !== undefined || f.maximum !== undefined) && (
                            <p className="text-xs text-muted-foreground tabular-nums">
                              {t('sensors.toolSettings.range', undefined, {
                                min: f.minimum ?? '-',
                                max: f.maximum ?? '-',
                              })}
                            </p>
                          )}
                          {f.tier === 'T1' && (
                            <p className="flex items-start gap-1 text-xs text-warning">
                              <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
                              {t('sensors.toolSettings.impactWarning')}
                            </p>
                          )}
                          {locked && (
                            <p className="flex items-start gap-1 text-xs text-destructive">
                              <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
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
                  </AccordionContent>
                </AccordionItem>
              )
            })}
          </Accordion>
        )}

        {formProblem && (
          <p className="text-xs text-destructive" role="alert">
            {formProblem}
          </p>
        )}

        <div className="flex flex-wrap gap-2">
          {anyChanged && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => setDraft({})}
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden />
              {t('sensors.toolSettings.resetTool')}
            </Button>
          )}
          <Button
            type="button"
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
      </AccordionContent>

      {open && needsSave && (
        <div
          className="sticky bottom-0 z-10 mt-auto flex flex-wrap items-center gap-2 border-t bg-background px-3 py-2"
          data-testid={`tool-settings-savebar-${item.tool}`}
        >
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span className="h-2 w-2 rounded-full bg-warning" aria-hidden />
            {dirty ? t('sensors.toolSettings.unsaved') : t('sensors.toolSettings.needsAttention')}
          </span>
          <span className="ms-auto flex gap-2">
            {dirty && (
              <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={discard}>
                {t('sensors.toolSettings.discard')}
              </Button>
            )}
            <Button
              type="button"
              size="sm"
              onClick={() => void save()}
              disabled={busy || fields.length === 0}
              aria-label={t('sensors.toolSettings.saveTool', undefined, { tool: item.tool })}
            >
              {t('sensors.toolSettings.save')}
            </Button>
          </span>
        </div>
      )}
    </AccordionItem>
  )
}

/**
 * The sensor's tools as a list of collapsed rows: tools with changes first,
 * a search over tool and option names, and the open tools remembered per
 * sensor in this browser.
 */
export function ToolSettingsList({
  sensorId,
  items,
  versions,
  onChanged,
}: {
  sensorId: string
  items: SensorToolSettings[]
  /** Tool versions from the sensor's current manifest, by tool name. */
  versions?: ReadonlyMap<string, string>
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const listRef = useRef<HTMLDivElement>(null)
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState<string[]>(() => readOpenTools(sensorId))

  const rows = useMemo<ToolRow[]>(() => {
    const out = items.map((item) => {
      const fields = toolSettingFields(item.schema)
      const saved = draftFromValues(fields, item.values)
      return {
        item,
        fields,
        saved,
        attention: item.problems.length > 0 || changedFields(fields, saved).length > 0,
      }
    })
    return out.sort(
      (a, b) => Number(b.attention) - Number(a.attention) || a.item.tool.localeCompare(b.item.tool)
    )
  }, [items])

  const q = query.trim().toLowerCase()
  const matched = useMemo(() => {
    const out = new Map<string, Set<string>>()
    if (q === '') return out
    for (const r of rows) {
      const keys = new Set(
        r.fields.filter((f) => fieldMatches(f, fieldLabel(f, r.item.tool, t), q)).map((f) => f.key)
      )
      if (keys.size > 0 || r.item.tool.toLowerCase().includes(q)) out.set(r.item.tool, keys)
    }
    return out
  }, [rows, q, t])
  const isVisible = (r: ToolRow) => q === '' || matched.has(r.item.tool)
  const anyVisible = rows.some(isVisible)

  const updateOpen = useCallback(
    (next: string[]) => {
      setOpen(next)
      writeOpenTools(sensorId, next)
    },
    [sensorId]
  )

  const onOpenChange = (next: string[]) => {
    const opened = next.filter((tool) => !open.includes(tool))
    updateOpen(next)
    // On a phone an opened tool takes the screen: bring its row to the top.
    if (opened.length === 1 && isPhoneWidth()) {
      requestAnimationFrame(() => {
        const el = Array.from(
          listRef.current?.querySelectorAll<HTMLElement>('[data-tool]') ?? []
        ).find((n) => n.dataset.tool === opened[0])
        el?.scrollIntoView?.({ block: 'start' })
      })
    }
  }

  const onSearch = (value: string) => {
    setQuery(value)
    const nq = value.trim().toLowerCase()
    if (nq === '') return
    // Open every tool that matches by name or by one of its options.
    const hits = rows
      .filter(
        (r) =>
          r.item.tool.toLowerCase().includes(nq) ||
          r.fields.some((f) => fieldMatches(f, fieldLabel(f, r.item.tool, t), nq))
      )
      .map((r) => r.item.tool)
    const add = hits.filter((tool) => !open.includes(tool))
    if (add.length > 0) updateOpen([...open, ...add])
  }

  // Bring the first matching option into view once its tool and group are open.
  useEffect(() => {
    if (q === '') return
    const el = listRef.current?.querySelector<HTMLElement>('[data-search-match="true"]')
    el?.scrollIntoView?.({ block: 'center' })
  }, [q])

  const empty = useMemo(() => new Set<string>(), [])

  return (
    <div className="space-y-3">
      <div className="relative">
        <Search
          className="pointer-events-none absolute top-1/2 left-2.5 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          type="search"
          className="ps-8"
          value={query}
          onChange={(e) => onSearch(e.target.value)}
          placeholder={t('sensors.toolSettings.searchPlaceholder')}
          aria-label={t('sensors.toolSettings.searchLabel')}
        />
      </div>
      {!anyVisible && (
        <p className="text-sm text-muted-foreground">
          {t('sensors.toolSettings.searchEmpty', undefined, { query: query.trim() })}
        </p>
      )}
      <div ref={listRef} hidden={!anyVisible}>
        <Accordion
          type="multiple"
          value={open}
          onValueChange={onOpenChange}
          className="rounded-md border"
        >
          {rows.map((row) => (
            <ToolSettingsItem
              key={`${row.item.tool}-${row.item.schema_digest}-${row.item.updated_at ?? ''}`}
              sensorId={sensorId}
              row={row}
              version={versions?.get(row.item.tool)}
              open={open.includes(row.item.tool)}
              matches={matched.get(row.item.tool) ?? empty}
              query={q}
              hidden={!isVisible(row)}
              onChanged={onChanged}
            />
          ))}
        </Accordion>
      </div>
    </div>
  )
}

/**
 * The sensor's tool settings, for owners and administrators (sensors:write):
 * a collapsible row per tool of the current manifest that declares settings.
 */
export function SensorToolSettingsSection({ sensorId }: { sensorId: string }) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const { data, error, isLoading, mutate } = useSensorToolSettings(sensorId, canWrite)
  const { data: manifests } = useSensorManifests(sensorId, canWrite)
  const versions = useMemo(() => {
    const current = manifests?.items.find((v) => v.current)
    return new Map(
      (current?.manifest.tools ?? [])
        .filter((tool) => tool.version)
        .map((tool) => [tool.name, tool.version as string])
    )
  }, [manifests])
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
      {items.length > 0 && (
        <ToolSettingsList
          sensorId={sensorId}
          items={items}
          versions={versions}
          onChanged={() => void mutate()}
        />
      )}
    </DetailSection>
  )
}
