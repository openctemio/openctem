'use client'

/**
 * One capability standard param as a form field: the workflow editor's
 * inspector and the scan wizard's step settings both render it, so a param
 * looks and validates the same everywhere (the contract's type, enum and
 * bounds, through paramValue).
 */

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import type { CapabilityParam } from '../lib/capability-graph'
import { paramValue } from '../lib/step-settings'

export function ParamField({
  param,
  value,
  readOnly,
  idPrefix = 'param',
  onChange,
}: {
  param: CapabilityParam
  value: unknown
  readOnly?: boolean
  /** Distinguishes the same param shown at several depths. */
  idPrefix?: string
  onChange: (value: unknown) => void
}) {
  const { t } = useTranslation()
  const [error, setError] = useState<string | undefined>()
  const id = `${idPrefix}-${param.name}`
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
