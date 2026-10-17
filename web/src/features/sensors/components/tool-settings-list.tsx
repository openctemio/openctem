'use client'

/**
 * The shared tool settings list (api docs/architecture/sensors.md, "Tool
 * settings"): one collapsed row per tool, a search over tool and option
 * names, groups of options generated from the tool's own settings schema
 * (nothing here knows a tool), and one save bar per tool.
 *
 * Two modes:
 * - "organization": the organization's defaults (Settings → Scanning → Tool
 *   defaults); an option is changed when it differs from the tool default.
 * - "sensor": one sensor's overrides; every option shows its effective value
 *   and where it comes from (tool default, organization or this sensor), with
 *   Override and Reset to the organization (or tool) default.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle, Pencil, RotateCcw, Search } from 'lucide-react'
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
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  toolSettingsProblems,
  type ToolSettingsProblem,
} from '@/lib/api/sensor-tool-settings-hooks'
import { scrollIntoContainer } from '@/lib/scroll-into-container'
import { cn } from '@/lib/utils'

import {
  changeSummaryList,
  defaultText,
  draftFromValues,
  fieldMatches,
  isChangedValue,
  isSetValue,
  problemKey,
  toolSettingFields,
  valuesFromDraft,
  valueText,
  type Draft,
  type DraftValue,
  type ToolSettingField,
} from '../lib/tool-settings'

export type T = ReturnType<typeof useTranslation>['t']

export type ToolSettingsMode = 'organization' | 'sensor'

/** One tool of the list, whatever the layer. */
export interface ToolSettingsEntry {
  tool: string
  /** The tool's settings schema; null when no sensor reports it any more. */
  schema: Record<string, unknown> | null
  schemaDigest: string
  /** The values stored in this layer. */
  values: Record<string, unknown>
  stored: boolean
  updatedAt?: string
  /** Stored values that no longer fit the tool (saving again or resetting fixes them). */
  problems: ToolSettingsProblem[]
  /** Sensor mode: the organization's defaults the sensor inherits. */
  inherited?: Record<string, unknown>
  /** Warnings shown at the top of the open tool (one list each). */
  notices?: { title: string; items: string[] }[]
  /** A short line next to the tool name (organization mode: how many sensors). */
  meta?: string
}

const SELECT_CLASS =
  'h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm shadow-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50'

/** Bound on the remembered open tools (the value comes from browser storage). */
const MAX_REMEMBERED = 64

/** The tools open last time under key; [] when storage is unavailable. */
function readOpenTools(key: string): string[] {
  try {
    const raw = window.localStorage.getItem(key)
    const parsed: unknown = raw ? JSON.parse(raw) : []
    if (!Array.isArray(parsed)) return []
    return parsed.filter((v): v is string => typeof v === 'string').slice(0, MAX_REMEMBERED)
  } catch {
    return []
  }
}

function writeOpenTools(key: string, tools: string[]) {
  try {
    window.localStorage.setItem(key, JSON.stringify(tools.slice(0, MAX_REMEMBERED)))
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

export function fieldLabel(f: ToolSettingField, tool: string, t: T): string {
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

/** The value an option falls back to when this layer leaves it empty. */
interface BaseValue {
  /** In draft form (booleans as booleans, numbers as text). */
  value: DraftValue
  text: string
  source: 'tenant' | 'default'
}

function baseValue(f: ToolSettingField, inherited: Draft | undefined): BaseValue {
  const inh = inherited?.[f.key]
  if (inh !== undefined) return { value: inh, text: valueText(inh), source: 'tenant' }
  const d = f.defaultValue
  const value: DraftValue =
    d === undefined
      ? undefined
      : typeof d === 'boolean'
        ? d
        : Array.isArray(d)
          ? d.map(String)
          : String(d)
  return { value, text: defaultText(f), source: 'default' }
}

function FieldInput({
  id,
  f,
  value,
  base,
  disabled,
  onChange,
  t,
}: {
  id: string
  f: ToolSettingField
  value: DraftValue
  base: BaseValue
  disabled: boolean
  onChange: (v: DraftValue) => void
  t: T
}) {
  const placeholder = base.text
  switch (f.kind) {
    case 'boolean': {
      const baseOn = base.value === true
      const checked = typeof value === 'boolean' ? value : baseOn
      return (
        <Switch
          id={id}
          checked={checked}
          disabled={disabled}
          onCheckedChange={(c) =>
            onChange(base.value !== undefined && c === baseOn ? undefined : c)
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
              ? base.source === 'tenant'
                ? t('sensors.toolSettings.orgOption', undefined, { value: placeholder })
                : t('sensors.toolSettings.defaultOption', undefined, { value: placeholder })
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
      const selected = Array.isArray(value) ? value : Array.isArray(base.value) ? base.value : []
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
  entry: ToolSettingsEntry
  fields: ToolSettingField[]
  saved: Draft
  /** Sensor mode: the inherited organization values, in draft form. */
  inherited?: Draft
  /** Changed or overridden options, problems or notices: listed first. */
  attention: boolean
}

/** Options this layer sets: changed from the default (organization) or set at all (sensor). */
function setFields(mode: ToolSettingsMode, fields: ToolSettingField[], draft: Draft) {
  return fields.filter((f) =>
    mode === 'sensor' ? isSetValue(draft[f.key]) : isChangedValue(f, draft[f.key])
  )
}

function ToolSummary({
  row,
  draft,
  mode,
  t,
}: {
  row: ToolRow
  draft: Draft
  mode: ToolSettingsMode
  t: T
}) {
  const set = setFields(mode, row.fields, draft)
  if (set.length > 0) {
    return (
      <>
        {t(
          mode === 'sensor'
            ? 'sensors.toolSettings.overrides'
            : 'sensors.toolSettings.summaryChanged',
          undefined,
          { count: set.length, list: changeSummaryList(set, draft) }
        )}
      </>
    )
  }
  const inheritedCount = row.inherited ? Object.keys(row.inherited).length : 0
  if (mode === 'sensor' && inheritedCount > 0) {
    return <>{t('sensors.toolSettings.inheritsOrg', undefined, { count: inheritedCount })}</>
  }
  return <>{t('sensors.toolSettings.allDefaults')}</>
}

const SOURCE_KEYS: Record<string, string> = {
  sensor: 'sensors.toolSettings.source.sensor',
  tenant: 'sensors.toolSettings.source.tenant',
  default: 'sensors.toolSettings.source.default',
  scan: 'sensors.toolSettings.source.scan',
}

export function sourceLabel(source: string, t: T): string {
  const key = SOURCE_KEYS[source]
  return key ? t(key) : t('sensors.toolSettings.unset')
}

function ToolSettingsItem({
  mode,
  row,
  version,
  open,
  matches,
  query,
  hidden,
  canEdit,
  save: saveValues,
  reset: resetValues,
  onChanged,
  extra,
}: {
  mode: ToolSettingsMode
  row: ToolRow
  version?: string
  open: boolean
  /** Filtered out by the search: kept mounted so unsaved changes survive. */
  hidden: boolean
  /** Keys of the options that match the search. */
  matches: ReadonlySet<string>
  query: string
  canEdit: boolean
  save: (tool: string, values: Record<string, unknown>) => Promise<void>
  reset: (tool: string) => Promise<void>
  onChanged: () => void
  extra?: ReactNode
}) {
  const { t } = useTranslation()
  const { entry, fields, saved, inherited } = row
  const [draft, setDraft] = useState<Draft>(saved)
  const [problems, setProblems] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
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
  const needsSave = canEdit && (dirty || entry.problems.length > 0)
  const anySet = setFields(mode, fields, draft).length > 0

  const save = async () => {
    setBusy(true)
    setProblems({})
    const values = valuesFromDraft(fields, draft)
    try {
      if (Object.keys(values).length === 0 && entry.stored) {
        // Nothing set in this layer any more: drop what is stored.
        await resetValues(entry.tool)
        toast.success(t('sensors.toolSettings.resetDone', undefined, { tool: entry.tool }))
      } else {
        await saveValues(entry.tool, values)
        toast.success(t('sensors.toolSettings.saved', undefined, { tool: entry.tool }))
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
  const resetKey = (b: BaseValue) =>
    mode === 'sensor'
      ? b.source === 'tenant'
        ? 'sensors.toolSettings.resetToOrg'
        : 'sensors.toolSettings.resetToTool'
      : 'sensors.toolSettings.resetOption'
  const resetLabelKey = (b: BaseValue) =>
    mode === 'sensor'
      ? b.source === 'tenant'
        ? 'sensors.toolSettings.resetToOrgLabel'
        : 'sensors.toolSettings.resetToToolLabel'
      : 'sensors.toolSettings.resetOptionLabel'

  return (
    <AccordionItem
      value={entry.tool}
      data-tool={entry.tool}
      data-testid={`tool-settings-${entry.tool}`}
      hidden={hidden}
      className="flex flex-col max-sm:data-[state=open]:min-h-[calc(100dvh-8rem)]"
    >
      <AccordionTrigger className="min-w-0 items-center px-3 py-2.5 hover:no-underline">
        <span className="flex min-w-0 flex-1 flex-col gap-0.5">
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-mono text-sm font-medium">{entry.tool}</span>
            {version && (
              <span className="text-xs font-normal text-muted-foreground tabular-nums">
                {version}
              </span>
            )}
            {entry.meta && (
              <span className="text-xs font-normal text-muted-foreground">{entry.meta}</span>
            )}
            {(entry.problems.length > 0 || (entry.notices?.length ?? 0) > 0) && (
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
            data-testid={`tool-settings-summary-${entry.tool}`}
          >
            <ToolSummary row={row} draft={draft} mode={mode} t={t} />
          </span>
        </span>
      </AccordionTrigger>
      <AccordionContent className="space-y-3 px-3">
        {entry.problems.length > 0 && (
          <div
            className="flex gap-2 rounded-md bg-destructive/10 p-2 text-xs text-destructive"
            role="alert"
          >
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden />
            <div className="space-y-1">
              <p>{t('sensors.toolSettings.staleWarning')}</p>
              <ul className="list-disc pl-4">
                {entry.problems.map((p) => (
                  <li key={p.path}>
                    <span className="font-mono">{problemKey(p.path) || entry.tool}</span>:{' '}
                    {p.message}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
        {entry.notices?.map((n) => (
          <div
            key={n.title}
            className="flex gap-2 rounded-md bg-destructive/10 p-2 text-xs text-destructive"
            role="alert"
            data-testid={`tool-settings-notice-${entry.tool}`}
          >
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden />
            <div className="min-w-0 space-y-1">
              <p>{n.title}</p>
              <ul className="list-disc pl-4 break-words">
                {n.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        ))}

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
              const changedCount = setFields(mode, g.fields, draft).length
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
                          {t(
                            mode === 'sensor'
                              ? 'sensors.toolSettings.groupOverridden'
                              : 'sensors.toolSettings.groupChanged',
                            undefined,
                            { count: changedCount }
                          )}
                        </Badge>
                      )}
                    </span>
                  </AccordionTrigger>
                  <AccordionContent className="space-y-4 px-3">
                    {g.fields.map((f) => {
                      const id = `tool-setting-${entry.tool}-${f.key}`
                      const locked = f.tier === 'T2'
                      const problem = problems[f.key]
                      const value = draft[f.key]
                      const changed =
                        mode === 'sensor' ? isSetValue(value) : isChangedValue(f, value)
                      const base = baseValue(f, inherited)
                      const label = fieldLabel(f, entry.tool, t)
                      const match = matches.has(f.key)
                      const effectiveText = changed ? valueText(value) : base.text
                      const effectiveSource = changed ? 'sensor' : base.source
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
                          <div className="flex items-start gap-2">
                            <span className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
                              {changed && (
                                <span
                                  className="h-2 w-2 shrink-0 rounded-full bg-primary"
                                  data-testid={`tool-setting-changed-${f.key}`}
                                  title={t(
                                    mode === 'sensor'
                                      ? 'sensors.toolSettings.overriddenHere'
                                      : 'sensors.toolSettings.changedFromDefault'
                                  )}
                                >
                                  <span className="sr-only">
                                    {t(
                                      mode === 'sensor'
                                        ? 'sensors.toolSettings.overriddenHere'
                                        : 'sensors.toolSettings.changedFromDefault'
                                    )}
                                  </span>
                                </span>
                              )}
                              <Label htmlFor={id}>{label}</Label>
                              <FieldTags f={f} t={t} />
                            </span>
                            {canEdit && changed && !locked && (
                              <Button
                                type="button"
                                size="sm"
                                variant="ghost"
                                className="h-7 shrink-0 px-2 text-xs"
                                disabled={busy}
                                aria-label={t(resetLabelKey(base), undefined, { option: label })}
                                onClick={() => setDraft((d) => ({ ...d, [f.key]: undefined }))}
                              >
                                <RotateCcw className="h-3.5 w-3.5" aria-hidden />
                                <span className="max-sm:sr-only">{t(resetKey(base))}</span>
                              </Button>
                            )}
                            {canEdit && mode === 'sensor' && !changed && !locked && (
                              <Button
                                type="button"
                                size="sm"
                                variant="ghost"
                                className="h-7 shrink-0 px-2 text-xs"
                                disabled={busy}
                                aria-label={t('sensors.toolSettings.overrideLabel', undefined, {
                                  option: label,
                                })}
                                onClick={() => {
                                  setDraft((d) => ({
                                    ...d,
                                    [f.key]: base.value ?? (f.kind === 'boolean' ? false : ''),
                                  }))
                                  requestAnimationFrame(() => document.getElementById(id)?.focus())
                                }}
                              >
                                <Pencil className="h-3.5 w-3.5" aria-hidden />
                                <span className="max-sm:sr-only">
                                  {t('sensors.toolSettings.override')}
                                </span>
                              </Button>
                            )}
                          </div>
                          {mode === 'sensor' && (
                            <p
                              className="text-xs text-muted-foreground"
                              data-testid={`tool-setting-source-${f.key}`}
                              data-source={effectiveSource}
                            >
                              {t('sensors.toolSettings.effectiveLine', undefined, {
                                value: effectiveText || t('sensors.toolSettings.unset'),
                                source: sourceLabel(effectiveSource, t),
                              })}
                            </p>
                          )}
                          <FieldInput
                            id={id}
                            f={f}
                            value={value}
                            base={base}
                            disabled={!canEdit || busy || locked}
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
                              {t('sensors.toolSettings.impactWarning')}{' '}
                              {t('sensors.toolSettings.impactStepUp')}
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

        {canEdit && anySet && (
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => setDraft({})}
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden />
              {t(
                mode === 'sensor'
                  ? 'sensors.toolSettings.resetAllOverrides'
                  : 'sensors.toolSettings.resetTool'
              )}
            </Button>
          </div>
        )}

        {extra}
      </AccordionContent>

      {open && needsSave && (
        <div
          className="sticky bottom-0 z-10 mt-auto flex flex-wrap items-center gap-2 border-t bg-background px-3 py-2"
          data-testid={`tool-settings-savebar-${entry.tool}`}
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
              disabled={busy || (fields.length === 0 && !entry.stored)}
              aria-label={t('sensors.toolSettings.saveTool', undefined, { tool: entry.tool })}
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
 * Tools as a list of collapsed rows: tools that need attention or set
 * something first, a search over tool and option names, and the open tools
 * remembered in this browser under storageKey.
 */
export function ToolSettingsList({
  mode,
  storageKey,
  items,
  versions,
  canEdit = true,
  save,
  reset,
  onChanged,
  renderExtra,
}: {
  mode: ToolSettingsMode
  storageKey: string
  items: ToolSettingsEntry[]
  /** Tool versions by tool name (sensor mode: the current manifest's). */
  versions?: ReadonlyMap<string, string>
  canEdit?: boolean
  save: (tool: string, values: Record<string, unknown>) => Promise<void>
  reset: (tool: string) => Promise<void>
  onChanged: () => void
  renderExtra?: (tool: string) => ReactNode
}) {
  const { t } = useTranslation()
  const listRef = useRef<HTMLDivElement>(null)
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState<string[]>(() => readOpenTools(storageKey))

  const rows = useMemo<ToolRow[]>(() => {
    const out = items.map((entry) => {
      const fields = toolSettingFields(entry.schema)
      const saved = draftFromValues(fields, entry.values)
      const inherited =
        mode === 'sensor' && entry.inherited ? draftFromValues(fields, entry.inherited) : undefined
      return {
        entry,
        fields,
        saved,
        inherited,
        attention:
          entry.problems.length > 0 ||
          (entry.notices?.length ?? 0) > 0 ||
          setFields(mode, fields, saved).length > 0,
      }
    })
    return out.sort(
      (a, b) =>
        Number(b.attention) - Number(a.attention) || a.entry.tool.localeCompare(b.entry.tool)
    )
  }, [items, mode])

  const q = query.trim().toLowerCase()
  const matched = useMemo(() => {
    const out = new Map<string, Set<string>>()
    if (q === '') return out
    for (const r of rows) {
      const keys = new Set(
        r.fields.filter((f) => fieldMatches(f, fieldLabel(f, r.entry.tool, t), q)).map((f) => f.key)
      )
      if (keys.size > 0 || r.entry.tool.toLowerCase().includes(q)) out.set(r.entry.tool, keys)
    }
    return out
  }, [rows, q, t])
  const isVisible = (r: ToolRow) => q === '' || matched.has(r.entry.tool)
  const anyVisible = rows.some(isVisible)

  const updateOpen = useCallback(
    (next: string[]) => {
      setOpen(next)
      writeOpenTools(storageKey, next)
    },
    [storageKey]
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
        scrollIntoContainer(el, 'start')
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
          r.entry.tool.toLowerCase().includes(nq) ||
          r.fields.some((f) => fieldMatches(f, fieldLabel(f, r.entry.tool, t), nq))
      )
      .map((r) => r.entry.tool)
    const add = hits.filter((tool) => !open.includes(tool))
    if (add.length > 0) updateOpen([...open, ...add])
  }

  // Bring the first matching option into view once its tool and group are open.
  useEffect(() => {
    if (q === '') return
    const el = listRef.current?.querySelector<HTMLElement>('[data-search-match="true"]')
    scrollIntoContainer(el, 'center')
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
              key={`${row.entry.tool}-${row.entry.schemaDigest}-${row.entry.updatedAt ?? ''}-${JSON.stringify(row.entry.inherited ?? {})}`}
              mode={mode}
              row={row}
              version={versions?.get(row.entry.tool)}
              open={open.includes(row.entry.tool)}
              matches={matched.get(row.entry.tool) ?? empty}
              query={q}
              hidden={!isVisible(row)}
              canEdit={canEdit}
              save={save}
              reset={reset}
              onChanged={onChanged}
              extra={renderExtra?.(row.entry.tool)}
            />
          ))}
        </Accordion>
      </div>
    </div>
  )
}
