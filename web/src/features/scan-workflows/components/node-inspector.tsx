'use client'

import { useState } from 'react'
import { AlertTriangle, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability, CapabilityParam, GraphIssue } from '../lib/capability-graph'
import { paramValue, selectionOf, toolsMissingParams, withParam } from '../lib/step-settings'
import { ToolSelectionField } from './tool-selection-field'

/**
 * The selected step's settings: how it picks its tool (auto, prefer, pin)
 * and the standard params of its capability. The form is generated from the
 * capability contract (GET /scans/stages), so only the contract's params can
 * be entered; the API validates every save.
 */
export function NodeInspector({
  step,
  capability,
  issues = [],
  readOnly,
  onChange,
  onClose,
}: {
  step: ScanWorkflowStep
  capability: Capability | null
  /** What the API's check of the draft says about this step. */
  issues?: GraphIssue[]
  readOnly?: boolean
  onChange: (step: ScanWorkflowStep) => void
  onClose: () => void
}) {
  const { t } = useTranslation()
  const mode = selectionOf(step)
  const missing = capability ? toolsMissingParams(capability, step.config) : {}
  // Settings outside the capability contract (a pinned tool's own keys,
  // or keys an older template stored): shown so they can be removed.
  const contract = new Set(capability?.params.map((p) => p.name) ?? [])
  const extra = capability
    ? Object.entries(step.config ?? {}).filter(([k]) => !contract.has(k) && k !== 'exclude')
    : []

  return (
    <aside
      aria-label={t('workflowStages.inspector.aria', 'Settings of {name}', { name: step.name })}
      className="flex w-80 shrink-0 flex-col border-s bg-background"
    >
      <div className="flex items-start justify-between gap-2 border-b px-4 py-3">
        <div className="min-w-0">
          <h2 className="truncate text-sm font-semibold">{step.name}</h2>
          {capability ? (
            <p className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
              <span className="truncate">{capability.name}</span>
              <Badge variant="outline" className="px-1 py-0 font-mono text-[10px]">
                {capability.id}
              </Badge>
              <Badge variant="outline" className="px-1 py-0 text-[10px]">
                {capability.tier}
              </Badge>
            </p>
          ) : (
            <p className="text-xs text-muted-foreground">
              {t('workflowStages.inspector.noContract')}
            </p>
          )}
        </div>
        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          aria-label={t('workflowStages.inspector.close')}
        >
          <X className="h-4 w-4" />
        </Button>
      </div>

      <ScrollArea className="flex-1">
        <div className="space-y-5 px-4 py-4">
          {issues.length > 0 && (
            <ul className="space-y-2" aria-label={t('workflowStages.inspector.problems')}>
              {issues.map((is, i) => (
                <li
                  key={`${is.code}-${i}`}
                  className="flex items-start gap-1.5 rounded-md border px-2 py-1.5 text-xs"
                >
                  <AlertTriangle className="mt-px h-3 w-3 shrink-0 text-warning" />
                  <span>
                    {is.message}
                    {is.fix && <span className="block text-muted-foreground">{is.fix}</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {!capability ? (
            <p className="text-xs text-muted-foreground">
              {t(
                'workflowStages.inspector.noContractBody',
                "{tool} has no capability contract: it runs with its own settings on the scan's targets and takes no data from earlier steps.",
                { tool: step.tool || t('workflowStages.inspector.thisTool') }
              )}
            </p>
          ) : (
            <>
              <ToolSelectionField
                step={step}
                capability={capability}
                mode={mode}
                missing={missing}
                readOnly={readOnly}
                onChange={onChange}
              />
              <section className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  {t('workflowStages.inspector.settings')}
                </h3>
                {capability.params.length === 0 && (
                  <p className="text-xs text-muted-foreground">
                    {t('workflowStages.inspector.noSettings')}
                  </p>
                )}
                {capability.params.map((p) => (
                  <ParamField
                    key={`${step.id}-${p.name}`}
                    param={p}
                    value={step.config?.[p.name]}
                    readOnly={readOnly}
                    onChange={(v) =>
                      onChange({ ...step, config: withParam(step.config, p.name, v) })
                    }
                  />
                ))}
              </section>
              {extra.length > 0 && (
                <section className="space-y-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                    {t('workflowStages.inspector.otherSettings')}
                  </h3>
                  <p className="text-xs text-muted-foreground">
                    {t('workflowStages.inspector.otherSettingsHint')}
                  </p>
                  <ul className="space-y-1">
                    {extra.map(([k, v]) => (
                      <li key={k} className="flex items-center gap-2 text-xs">
                        <code className="truncate">
                          {k} = {JSON.stringify(v)}
                        </code>
                        {!readOnly && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="ms-auto h-6 px-2 text-xs"
                            aria-label={t('workflowStages.inspector.removeAria', 'Remove {key}', {
                              key: k,
                            })}
                            onClick={() =>
                              onChange({ ...step, config: withParam(step.config, k, undefined) })
                            }
                          >
                            {t('workflowStages.inspector.remove')}
                          </Button>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </>
          )}

          <section className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              {t('workflowStages.inspector.run')}
            </h3>
            <NumberField
              id={`${step.id}-timeout`}
              label={t('workflowStages.inspector.timeout')}
              help={t('workflowStages.inspector.timeoutHelp')}
              value={step.timeout_seconds ?? 3600}
              min={60}
              max={86400}
              readOnly={readOnly}
              onChange={(n) => onChange({ ...step, timeout_seconds: n ?? 3600 })}
            />
          </section>
        </div>
      </ScrollArea>
    </aside>
  )
}

function ParamField({
  param,
  value,
  readOnly,
  onChange,
}: {
  param: CapabilityParam
  value: unknown
  readOnly?: boolean
  onChange: (value: unknown) => void
}) {
  const { t } = useTranslation()
  const [error, setError] = useState<string | undefined>()
  const id = `param-${param.name}`
  const set = (raw: string | boolean | string[]) => {
    const r = paramValue(param, raw)
    setError(r.error)
    if (!r.error) onChange(r.value)
  }

  if (param.type === 'boolean') {
    return (
      <div className="flex items-start justify-between gap-3">
        <Label htmlFor={id} className="text-sm font-normal">
          {param.name}
          <span className="block text-xs text-muted-foreground">{param.description}</span>
        </Label>
        <Switch
          id={id}
          checked={value === true}
          disabled={readOnly}
          onCheckedChange={(c) => set(c)}
        />
      </div>
    )
  }

  if (param.type === 'string_list' && param.enum.length > 0) {
    const list = Array.isArray(value) ? (value as string[]) : []
    return (
      <fieldset className="space-y-1">
        <legend className="text-sm">{param.name}</legend>
        <p className="text-xs text-muted-foreground">{param.description}</p>
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {param.enum.map((opt) => (
            <label key={opt} className="flex items-center gap-1.5 text-xs">
              <Checkbox
                checked={list.includes(opt)}
                disabled={readOnly}
                onCheckedChange={(on) => set(on ? [...list, opt] : list.filter((x) => x !== opt))}
              />
              {opt}
            </label>
          ))}
        </div>
      </fieldset>
    )
  }

  if (param.type === 'string' && param.enum.length > 0) {
    return (
      <div className="space-y-1">
        <Label htmlFor={id} className="text-sm font-normal">
          {param.name}
        </Label>
        <Select
          value={typeof value === 'string' ? value : ''}
          disabled={readOnly}
          onValueChange={(v) => set(v)}
        >
          <SelectTrigger id={id} className="h-8 text-xs">
            <SelectValue placeholder={t('workflowStages.inspector.default')} />
          </SelectTrigger>
          <SelectContent>
            {param.enum.map((opt) => (
              <SelectItem key={opt} value={opt}>
                {opt}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">{param.description}</p>
      </div>
    )
  }

  const shown = Array.isArray(value)
    ? (value as unknown[]).join(', ')
    : value === undefined
      ? ''
      : String(value)
  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="text-sm font-normal">
        {param.name}
      </Label>
      <Input
        id={id}
        defaultValue={shown}
        disabled={readOnly}
        inputMode={param.type === 'integer' ? 'numeric' : undefined}
        placeholder={
          param.type === 'port_list' ? '80,443,8000-8100' : t('workflowStages.inspector.default')
        }
        aria-invalid={!!error}
        aria-describedby={`${id}-help`}
        className="h-8 text-xs"
        onBlur={(e) => set(e.target.value)}
      />
      <p
        id={`${id}-help`}
        className={error ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'}
      >
        {error ?? describeParam(param, t)}
      </p>
    </div>
  )
}

function describeParam(p: CapabilityParam, t: ReturnType<typeof useTranslation>['t']): string {
  const range =
    p.min !== undefined && p.max !== undefined
      ? t('workflowStages.inspector.range', ' ({min} to {max})', { min: p.min, max: p.max })
      : p.type === 'string_list'
        ? t('workflowStages.inspector.commaSeparated')
        : ''
  return `${p.description}${range}`
}

function NumberField({
  id,
  label,
  help,
  value,
  min,
  max,
  readOnly,
  onChange,
}: {
  id: string
  label: string
  help: string
  value: number
  min: number
  max: number
  readOnly?: boolean
  onChange: (n: number | undefined) => void
}) {
  const { t } = useTranslation()
  const [error, setError] = useState<string | undefined>()
  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="text-sm font-normal">
        {label}
      </Label>
      <Input
        id={id}
        type="number"
        min={min}
        max={max}
        defaultValue={value}
        disabled={readOnly}
        className="h-8 text-xs"
        aria-invalid={!!error}
        onBlur={(e) => {
          const n = Number(e.target.value)
          if (!Number.isInteger(n) || n < min || n > max) {
            setError(t('workflowStages.inspector.rangeError', '{min} to {max}.', { min, max }))
            return
          }
          setError(undefined)
          onChange(n)
        }}
      />
      <p className={error ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'}>
        {error ?? help}
      </p>
    </div>
  )
}
