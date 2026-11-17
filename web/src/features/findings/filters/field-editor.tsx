'use client'

import { useState } from 'react'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
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
import { AssigneeSelect } from '@/features/findings/components/assignee-select'
import { useTranslation } from '@/context/i18n-provider'
import { editableOps, type FieldContract, type FilterOp } from './model'
import { useFilterLabels } from './use-filter-labels'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** Fields whose dates look ahead (a deadline), so the quick picks do too. */
const FORWARD_TIME = /expires|deadline|due/

/** Fields picked from the member list instead of typed. */
const PERSON_FIELDS = new Set(['assigned_to', 'asset_owner_id'])

/** The first operator a field opens with. */
function defaultOp(field: FieldContract): FilterOp {
  const ops = editableOps(field)
  // A deadline is asked about ahead of now ("within 30 days"), not since.
  if (field.type === 'date-time' && FORWARD_TIME.test(field.name) && ops.includes('lte'))
    return 'lte'
  return ops[0] ?? 'in'
}

/** Whether a typed value is acceptable for the field (the API still validates). */
function validValues(field: FieldContract, op: FilterOp, values: string[]): boolean {
  if (values.length === 0) return false
  if (op === 'is_null') return values[0] === 'true' || values[0] === 'false'
  if (field.type === 'number' || field.type === 'integer') {
    return values.every((v) => v.trim() !== '' && Number.isFinite(Number(v)))
  }
  if (field.type === 'id') return values.every((v) => UUID_RE.test(v))
  if (field.type === 'enum' && field.enum) return values.every((v) => field.enum!.includes(v))
  return true
}

/**
 * How an operator takes its value: nothing but a yes or no, a list, or one
 * value. Changing between two operators of one shape ("is" to "is not", "≥"
 * to "≤") keeps what was entered.
 */
function opShape(op: FilterOp): 'null' | 'list' | 'one' {
  return op === 'is_null' ? 'null' : op === 'in' || op === 'not_in' ? 'list' : 'one'
}

/** The operator the editor opens on for a filter that already exists. */
function startOp(field: FieldContract, initial: FilterOp | undefined): FilterOp {
  const ops = editableOps(field)
  if (initial && ops.includes(initial)) return initial
  // "is not" is offered once: a filter written with `ne` opens on it.
  if (initial === 'ne' && ops.includes('not_in')) return 'not_in'
  return defaultOp(field)
}

/** A date value as the date field shows it, when it is a date and not a range from now. */
function dateText(values: string[]): string {
  const m = /^(\d{4}-\d{2}-\d{2})(T|$)/.exec(values[0] ?? '')
  return m ? m[1] : ''
}

export interface FieldEditorProps {
  field: FieldContract
  labels: ReturnType<typeof useFilterLabels>
  /** Back to the list of fields (Add filter); absent when editing one filter. */
  onBack?: () => void
  onApply: (op: FilterOp, values: string[]) => void
  /** The filter being edited: the editor opens on its operator and values. */
  initial?: { op: FilterOp; values: string[] }
}

/** How to write a value for fields with their own syntax (a domain, a name pattern). */
function valueHint(
  name: string,
  t: ReturnType<typeof useTranslation>['t']
): { placeholder: string; text: string } | undefined {
  switch (name) {
    case 'asset_domain':
      return {
        placeholder: t('findings.filter.placeholder.asset_domain', 'example.com, *.example.com'),
        text: t(
          'findings.filter.hint.asset_domain',
          'example.com covers the domain and every asset under it: its names, the addresses they resolve to, services on them, certificates and web applications. *.example.com leaves the domain itself out. Shared CDN addresses never count.'
        ),
      }
    case 'asset_name':
      return {
        placeholder: t('findings.filter.placeholder.asset_name', 'api-*, *.example.com'),
        text: t(
          'findings.filter.hint.asset_name',
          '* matches any characters and ? one character. At most 3 wildcards, and at least 3 other characters in a row.'
        ),
      }
  }
  return undefined
}

/**
 * The editor of one filter, typed by its field: the operators the contract
 * gives the field, then choices for an enum, a number or text, quick date
 * ranges, yes / no, a person. Add filter shows it after a field is picked; a
 * filter chip opens it on the chip's own operator and values (`initial`).
 */
export function FieldEditor({ field, labels, onBack, onApply, initial }: FieldEditorProps) {
  const { t } = useTranslation()
  const ops = editableOps(field)
  const [op, setOp] = useState<FilterOp>(() => startOp(field, initial?.op))
  const choices = field.type === 'enum' ? field.enum : undefined
  const [values, setValues] = useState<string[]>(() =>
    // A value the field no longer offers cannot be ticked, so it is not kept.
    (initial?.values ?? []).filter((v) => !choices || choices.includes(v))
  )
  const [text, setText] = useState(() =>
    !initial
      ? ''
      : field.type === 'date-time'
        ? dateText(initial.values)
        : choices || field.type === 'boolean' || initial.op === 'is_null'
          ? ''
          : initial.values.join(', ')
  )
  /** The value the edited filter has now, marked on a one-tap choice. */
  const current = (o: FilterOp, v: string) =>
    !!initial && startOp(field, initial.op) === o && initial.values[0] === v
  const title = labels.fieldLabel(field.name)
  const list = op === 'in' || op === 'not_in'
  const apply = (v: string[] = values, o: FilterOp = op) => {
    if (validValues(field, o, v)) onApply(o, v)
  }

  const header = (
    <div
      className={
        onBack ? 'flex items-center gap-1 border-b px-2 py-1.5' : 'border-b px-3 py-2 max-md:hidden'
      }
    >
      {onBack && (
        <Button
          variant="ghost"
          size="icon"
          onClick={onBack}
          aria-label={t('findings.filter.back', 'Back to fields')}
        >
          <ArrowLeft className="size-4 rtl:rotate-180" aria-hidden />
        </Button>
      )}
      <p className="text-sm font-medium">{title}</p>
    </div>
  )

  const opSelect =
    ops.length > 1 ? (
      <div className="space-y-1.5">
        <Label htmlFor="filter-op" className="text-xs">
          {t('findings.filter.operator', 'Condition')}
        </Label>
        <Select
          value={op}
          onValueChange={(v) => {
            const next = v as FilterOp
            // The same kind of value: what was entered stays.
            if (opShape(next) !== opShape(op)) {
              setValues([])
              setText('')
            }
            setOp(next)
          }}
        >
          <SelectTrigger id="filter-op">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ops.map((o) => (
              <SelectItem key={o} value={o}>
                {labels.opLabel(o, field)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    ) : null

  let body: React.ReactNode
  if (op === 'is_null') {
    body = (
      <div className="flex gap-2">
        <Button
          size="sm"
          variant={current('is_null', 'true') ? 'secondary' : 'outline'}
          aria-pressed={initial ? current('is_null', 'true') : undefined}
          onClick={() => apply(['true'])}
        >
          {t('findings.filter.isEmptyChoice', 'Is empty')}
        </Button>
        <Button
          size="sm"
          variant={current('is_null', 'false') ? 'secondary' : 'outline'}
          aria-pressed={initial ? current('is_null', 'false') : undefined}
          onClick={() => apply(['false'])}
        >
          {t('findings.filter.isSetChoice', 'Is set')}
        </Button>
      </div>
    )
  } else if (field.type === 'boolean') {
    body = (
      <div className="flex gap-2">
        <Button
          size="sm"
          variant={current('eq', 'true') ? 'secondary' : 'outline'}
          aria-pressed={initial ? current('eq', 'true') : undefined}
          onClick={() => apply(['true'], 'eq')}
        >
          {t('common.yes', 'Yes')}
        </Button>
        <Button
          size="sm"
          variant={current('eq', 'false') ? 'secondary' : 'outline'}
          aria-pressed={initial ? current('eq', 'false') : undefined}
          onClick={() => apply(['false'], 'eq')}
        >
          {t('common.no', 'No')}
        </Button>
      </div>
    )
  } else if (field.type === 'enum' && field.enum) {
    body = (
      <fieldset className="max-h-56 space-y-1 overflow-y-auto">
        <legend className="sr-only">{title}</legend>
        {field.enum.map((v) => (
          <label
            key={v}
            className="flex cursor-pointer items-center gap-2 rounded px-1 py-1 text-sm hover:bg-muted"
          >
            <Checkbox
              checked={values.includes(v)}
              onCheckedChange={(on) =>
                setValues((prev) => (on ? [...prev, v] : prev.filter((x) => x !== v)))
              }
            />
            {labels.valueLabel(field, v)}
          </label>
        ))}
      </fieldset>
    )
  } else if (field.type === 'date-time') {
    const forward = FORWARD_TIME.test(field.name)
    const presets = forward
      ? [
          ['P7D', 7],
          ['P30D', 30],
          ['P90D', 90],
        ]
      : [
          ['-P1D', 1],
          ['-P7D', 7],
          ['-P30D', 30],
          ['-P90D', 90],
        ]
    body = (
      <div className="space-y-3">
        <div className="flex flex-wrap gap-1.5">
          {presets.map(([value, n]) => (
            <Button
              key={value}
              size="sm"
              variant={current(op, String(value)) ? 'secondary' : 'outline'}
              aria-pressed={initial ? current(op, String(value)) : undefined}
              onClick={() => apply([String(value)])}
            >
              {labels.relative(String(value)) ?? String(n)}
            </Button>
          ))}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="filter-date" className="text-xs">
            {t('findings.filter.date', 'Date')}
          </Label>
          <Input
            id="filter-date"
            type="date"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </div>
        <Button
          size="sm"
          disabled={!/^\d{4}-\d{2}-\d{2}$/.test(text)}
          onClick={() => apply([`${text}T00:00:00Z`])}
        >
          {t('findings.filter.apply', 'Apply')}
        </Button>
      </div>
    )
  } else if (PERSON_FIELDS.has(field.name) && list) {
    body = (
      <AssigneeSelect
        placeholder={t('findings.filter.pickPerson', 'Pick a person…')}
        onChange={(user) => user && apply([user.id])}
      />
    )
  } else {
    const numeric = field.type === 'number' || field.type === 'integer'
    const hint = valueHint(field.name, t)
    const parsed = list
      ? text
          .split(',')
          .map((v) => v.trim())
          .filter(Boolean)
      : [text.trim()]
    body = (
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          apply(parsed.filter(Boolean))
        }}
      >
        <div className="space-y-1.5">
          <Label htmlFor="filter-value" className="text-xs">
            {list
              ? t('findings.filter.valuesHint', 'Values, separated by commas')
              : t('findings.filter.value', 'Value')}
          </Label>
          <Input
            id="filter-value"
            inputMode={numeric ? 'decimal' : undefined}
            maxLength={200}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={hint ? hint.placeholder : undefined}
            aria-describedby={hint ? 'filter-value-hint' : undefined}
            autoFocus
          />
          {hint && (
            <p id="filter-value-hint" className="text-xs text-muted-foreground">
              {hint.text}
            </p>
          )}
        </div>
        <Button size="sm" type="submit" disabled={!validValues(field, op, parsed.filter(Boolean))}>
          {t('findings.filter.apply', 'Apply')}
        </Button>
      </form>
    )
  }

  const showApply = field.type === 'enum' && field.enum && op !== 'is_null'
  return (
    <div>
      {header}
      <div className="space-y-3 p-3">
        {opSelect}
        {body}
        {showApply && (
          <Button size="sm" disabled={!validValues(field, op, values)} onClick={() => apply()}>
            {t('findings.filter.apply', 'Apply')}
          </Button>
        )}
      </div>
    </div>
  )
}
