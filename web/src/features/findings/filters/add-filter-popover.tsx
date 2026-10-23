'use client'

import { useEffect, useMemo, useState } from 'react'
import { ArrowLeft, Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { AssigneeSelect } from '@/features/findings/components/assignee-select'
import { useTranslation } from '@/context/i18n-provider'
import {
  editableOps,
  pickableFields,
  type FieldContract,
  type FieldGroup,
  type FilterContract,
  type FilterOp,
} from './model'
import { useFilterLabels } from './use-filter-labels'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const GROUP_LABELS: Record<FieldGroup, [string, string]> = {
  exploitation: ['findings.filter.group.exploitation', 'Exploitation'],
  finding: ['findings.filter.group.finding', 'Finding'],
  asset: ['findings.filter.group.asset', 'Asset'],
  work: ['findings.filter.group.work', 'Work'],
  other: ['findings.filter.group.other', 'Other'],
}

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

interface AddFilterPopoverProps {
  /** The contract, once loaded (the popover asks the page to load it when opened). */
  contract: FilterContract | undefined
  contractLoading: boolean
  contractFailed: boolean
  canReadAssets: boolean
  /** Fields the open saved view already sets: a filter on one would override the view. */
  lockedFields?: ReadonlySet<string>
  onOpenChange?: (open: boolean) => void
  onApply: (field: FieldContract, op: FilterOp, values: string[]) => void
}

/**
 * Add filter: a searchable, grouped list of every field the API offers this
 * viewer, then an editor typed by the field (choices for an enum, an operator
 * and a number, quick date ranges, yes / no...). It is generated from the
 * filter contract, so a field the API adds appears here with no web change.
 * Pressing `f` outside a text field opens it.
 */
export function AddFilterPopover({
  contract,
  contractLoading,
  contractFailed,
  canReadAssets,
  lockedFields,
  onOpenChange,
  onApply,
}: AddFilterPopoverProps) {
  const { t } = useTranslation()
  const labels = useFilterLabels()
  const [open, setOpenState] = useState(false)
  const [picked, setPicked] = useState<FieldContract | null>(null)

  const setOpen = (next: boolean) => {
    setOpenState(next)
    if (!next) setPicked(null)
    onOpenChange?.(next)
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'f' || e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return
      const el = e.target as HTMLElement | null
      if (
        el?.closest?.(
          'input, textarea, select, [contenteditable="true"], [role="combobox"], [role="listbox"], [role="menu"], [role="dialog"], [role="alertdialog"]'
        )
      )
        return
      e.preventDefault()
      setOpenState(true)
      onOpenChange?.(true)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onOpenChange])

  const groups = useMemo(
    () => (contract ? pickableFields(contract, { canReadAssets }) : []),
    [contract, canReadAssets]
  )

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="h-7 gap-1 rounded-full border-dashed px-2.5 text-xs"
          aria-keyshortcuts="f"
        >
          <Plus className="size-3" aria-hidden />
          {t('findings.filter.add', 'Add filter')}
          <kbd
            className="ms-1 rounded border px-1 font-sans text-[10px] text-muted-foreground"
            aria-hidden
          >
            f
          </kbd>
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-80 p-0"
        aria-label={t('findings.filter.add', 'Add filter')}
      >
        {picked ? (
          <FieldEditor
            key={picked.name}
            field={picked}
            labels={labels}
            onBack={() => setPicked(null)}
            onApply={(op, values) => {
              onApply(picked, op, values)
              setOpen(false)
            }}
          />
        ) : (
          <Command>
            <CommandInput placeholder={t('findings.filter.searchFields', 'Search fields…')} />
            <CommandList>
              {contractLoading && !contract && (
                <p className="px-3 py-4 text-sm text-muted-foreground" role="status">
                  {t('findings.filter.loading', 'Loading filters…')}
                </p>
              )}
              {contractFailed && !contract && (
                <p className="px-3 py-4 text-sm text-destructive" role="alert">
                  {t('findings.filter.loadFailed', 'The filters could not be loaded.')}
                </p>
              )}
              {contract && (
                <CommandEmpty>{t('findings.filter.noField', 'No matching field')}</CommandEmpty>
              )}
              {groups.map(({ group, fields }) => (
                <CommandGroup key={group} heading={t(...GROUP_LABELS[group])}>
                  {fields.map((f) => {
                    const label = labels.fieldLabel(f.name)
                    const locked = lockedFields?.has(f.name) ?? false
                    return (
                      <CommandItem
                        key={f.name}
                        value={`${label} ${f.name}`}
                        disabled={locked}
                        onSelect={() => setPicked(f)}
                      >
                        {label}
                        {locked && (
                          <span className="ms-auto text-xs text-muted-foreground">
                            {t('findings.filter.setByView', 'Set by the saved view')}
                          </span>
                        )}
                      </CommandItem>
                    )
                  })}
                </CommandGroup>
              ))}
            </CommandList>
          </Command>
        )}
      </PopoverContent>
    </Popover>
  )
}

interface FieldEditorProps {
  field: FieldContract
  labels: ReturnType<typeof useFilterLabels>
  onBack: () => void
  onApply: (op: FilterOp, values: string[]) => void
}

function FieldEditor({ field, labels, onBack, onApply }: FieldEditorProps) {
  const { t } = useTranslation()
  const ops = editableOps(field)
  const [op, setOp] = useState<FilterOp>(defaultOp(field))
  const [values, setValues] = useState<string[]>([])
  const [text, setText] = useState('')
  const title = labels.fieldLabel(field.name)
  const list = op === 'in' || op === 'not_in'
  const apply = (v: string[] = values, o: FilterOp = op) => {
    if (validValues(field, o, v)) onApply(o, v)
  }

  const header = (
    <div className="flex items-center gap-1 border-b px-2 py-1.5">
      <Button
        variant="ghost"
        size="icon"
        className="size-7"
        onClick={onBack}
        aria-label={t('findings.filter.back', 'Back to fields')}
      >
        <ArrowLeft className="size-4 rtl:rotate-180" aria-hidden />
      </Button>
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
            setOp(v as FilterOp)
            setValues([])
            setText('')
          }}
        >
          <SelectTrigger id="filter-op" className="h-8">
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
        <Button size="sm" variant="outline" onClick={() => apply(['true'])}>
          {t('findings.filter.isEmptyChoice', 'Is empty')}
        </Button>
        <Button size="sm" variant="outline" onClick={() => apply(['false'])}>
          {t('findings.filter.isSetChoice', 'Is set')}
        </Button>
      </div>
    )
  } else if (field.type === 'boolean') {
    body = (
      <div className="flex gap-2">
        <Button size="sm" variant="outline" onClick={() => apply(['true'], 'eq')}>
          {t('common.yes', 'Yes')}
        </Button>
        <Button size="sm" variant="outline" onClick={() => apply(['false'], 'eq')}>
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
              variant="outline"
              className="h-7 text-xs"
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
            className="h-8"
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
            className="h-8"
            inputMode={numeric ? 'decimal' : undefined}
            maxLength={200}
            value={text}
            onChange={(e) => setText(e.target.value)}
            autoFocus
          />
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
