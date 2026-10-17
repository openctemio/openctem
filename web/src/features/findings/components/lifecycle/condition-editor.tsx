'use client'

import { Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { CONDITION_FIELDS, type LifecycleCondition } from '../../api/use-finding-lifecycles'

/** At most 8 conditions per `when` or context (api limit). */
export const MAX_CONDITIONS = 8

const LIST_OPS = new Set(['in', 'not_in'])

/** The value as the text box shows it. */
export function conditionValueText(c: LifecycleCondition): string {
  if (Array.isArray(c.value)) return c.value.join(', ')
  if (c.value === undefined || c.value === null) return ''
  return String(c.value)
}

/** The typed value the API takes for a text box value. */
export function parseConditionValue(field: string, op: string, text: string): unknown {
  if (op === 'exists') return true
  if (field === 'is_kev') return text.trim() === 'true'
  if (LIST_OPS.has(op)) {
    return text
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
  }
  return text.trim()
}

interface ConditionEditorProps {
  conditions: LifecycleCondition[]
  onChange: (next: LifecycleCondition[]) => void
  disabled?: boolean
  /** Prefix of the inputs' ids and labels (two editors may share a page). */
  idPrefix: string
}

/**
 * Rows of "field operator value" from the closed catalog: severity, priority
 * class, KEV, source, finding type, tool. No expressions or patterns: the API
 * refuses anything else.
 */
export function ConditionEditor({
  conditions,
  onChange,
  disabled,
  idPrefix,
}: ConditionEditorProps) {
  const { t } = useTranslation()
  const fields = Object.keys(CONDITION_FIELDS)

  const set = (i: number, patch: Partial<LifecycleCondition> & { text?: string }) => {
    const next = conditions.map((c, j) => {
      if (j !== i) return c
      const field = patch.field ?? c.field
      const ops = CONDITION_FIELDS[field]?.ops ?? []
      const op = patch.op && ops.includes(patch.op) ? patch.op : ops.includes(c.op) ? c.op : ops[0]
      const text = patch.text ?? (patch.field ? '' : conditionValueText(c))
      return { field, op, value: parseConditionValue(field, op, text) }
    })
    onChange(next)
  }

  return (
    <div className="space-y-2">
      {conditions.map((c, i) => {
        const def = CONDITION_FIELDS[c.field]
        return (
          <div key={i} className="flex flex-wrap items-center gap-2">
            <Select value={c.field} onValueChange={(v) => set(i, { field: v })} disabled={disabled}>
              <SelectTrigger
                className="h-8 w-40"
                aria-label={t('findingLifecycle.condition.field', 'Field')}
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {fields.map((f) => (
                  <SelectItem key={f} value={f}>
                    {t(`findingLifecycle.condition.fields.${f}`, f)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={c.op} onValueChange={(v) => set(i, { op: v })} disabled={disabled}>
              <SelectTrigger
                className="h-8 w-36"
                aria-label={t('findingLifecycle.condition.op', 'Operator')}
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(def?.ops ?? []).map((o) => (
                  <SelectItem key={o} value={o}>
                    {t(`findingLifecycle.condition.ops.${o}`, o)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {c.op !== 'exists' && (
              <Input
                id={`${idPrefix}-value-${i}`}
                className="h-8 min-w-0 flex-1"
                value={conditionValueText(c)}
                disabled={disabled}
                list={def?.values ? `${idPrefix}-values-${c.field}` : undefined}
                placeholder={
                  LIST_OPS.has(c.op)
                    ? t('findingLifecycle.condition.listHint', 'Values, separated by commas')
                    : t('findingLifecycle.condition.value', 'Value')
                }
                aria-label={t('findingLifecycle.condition.value', 'Value')}
                onChange={(e) => set(i, { text: e.target.value })}
              />
            )}
            {def?.values && (
              <datalist id={`${idPrefix}-values-${c.field}`}>
                {def.values.map((v) => (
                  <option key={v} value={v} />
                ))}
              </datalist>
            )}
            <Button
              type="button"
              size="icon"
              variant="ghost"
              className="size-8"
              disabled={disabled}
              aria-label={t('findingLifecycle.condition.remove', 'Remove condition')}
              onClick={() => onChange(conditions.filter((_, j) => j !== i))}
            >
              <X className="size-4" />
            </Button>
          </div>
        )
      })}
      <Button
        type="button"
        size="sm"
        variant="outline"
        disabled={disabled || conditions.length >= MAX_CONDITIONS}
        onClick={() => onChange([...conditions, { field: 'severity', op: 'in', value: [] }])}
      >
        <Plus className="mr-1 size-3.5" />
        {t('findingLifecycle.condition.add', 'Add condition')}
      </Button>
    </div>
  )
}
