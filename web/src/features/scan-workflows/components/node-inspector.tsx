'use client'

import { useState } from 'react'
import { X } from 'lucide-react'
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
import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability, CapabilityParam } from '../lib/capability-graph'
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
  readOnly,
  onChange,
  onClose,
}: {
  step: ScanWorkflowStep
  capability: Capability | null
  readOnly?: boolean
  onChange: (step: ScanWorkflowStep) => void
  onClose: () => void
}) {
  const mode = selectionOf(step)
  const missing = capability ? toolsMissingParams(capability, step.config) : {}

  return (
    <aside
      aria-label={`Settings of ${step.name}`}
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
            <p className="text-xs text-muted-foreground">No capability contract</p>
          )}
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close settings">
          <X className="h-4 w-4" />
        </Button>
      </div>

      <ScrollArea className="flex-1">
        <div className="space-y-5 px-4 py-4">
          {!capability ? (
            <p className="text-xs text-muted-foreground">
              {step.tool || 'This tool'} has no capability contract: it runs with its own settings
              on the scan&apos;s targets and takes no data from earlier steps.
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
                  Settings
                </h3>
                {capability.params.length === 0 && (
                  <p className="text-xs text-muted-foreground">This capability has no settings.</p>
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
            </>
          )}

          <section className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Run
            </h3>
            <NumberField
              id={`${step.id}-timeout`}
              label="Timeout (seconds)"
              help="60 to 86400."
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
            <SelectValue placeholder="Default" />
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
        placeholder={param.type === 'port_list' ? '80,443,8000-8100' : 'Default'}
        aria-invalid={!!error}
        aria-describedby={`${id}-help`}
        className="h-8 text-xs"
        onBlur={(e) => set(e.target.value)}
      />
      <p
        id={`${id}-help`}
        className={error ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'}
      >
        {error ?? describeParam(param)}
      </p>
    </div>
  )
}

function describeParam(p: CapabilityParam): string {
  const range =
    p.min !== undefined && p.max !== undefined
      ? ` (${p.min} to ${p.max})`
      : p.type === 'string_list'
        ? ' (comma-separated)'
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
            setError(`${min} to ${max}.`)
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
