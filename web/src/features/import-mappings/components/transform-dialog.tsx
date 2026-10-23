'use client'

import { Plus, Trash2 } from 'lucide-react'
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
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { formatConst, parseConstInput, templateVars } from '../lib/mapping-model'
import type { ValueSpecObject } from '../types/import-mapping.types'

interface TransformDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  target: string
  spec: ValueSpecObject
  onChange: (spec: ValueSpecObject) => void
  readOnly: boolean
}

function setKey<K extends keyof ValueSpecObject>(
  spec: ValueSpecObject,
  key: K,
  value: ValueSpecObject[K] | undefined
): ValueSpecObject {
  const next = { ...spec }
  if (value === undefined) delete next[key]
  else next[key] = value
  return next
}

/** The transforms of one value, in the order the language applies them. */
export function TransformDialog({
  open,
  onOpenChange,
  target,
  spec,
  onChange,
  readOnly,
}: TransformDialogProps) {
  const { t } = useTranslation()
  const caseValue = spec.lower ? 'lower' : spec.upper ? 'upper' : 'none'
  const mapEntries = Object.entries(spec.map ?? {})
  const vars = spec.template !== undefined ? templateVars(spec.template) : []

  const setMapEntries = (entries: [string, string | number | boolean][]) => {
    onChange(setKey(spec, 'map', entries.length ? Object.fromEntries(entries) : undefined))
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {t('importMappings.transform.title', 'Transforms for {target}', {
              target: target || t('importMappings.table.noTarget', 'new row'),
            })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'importMappings.transform.description',
              'Applied in this order: first item, trim and case, split, value table, join, convert, size limit. The default replaces a missing or empty result.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <fieldset disabled={readOnly} className="grid gap-4">
            {spec.template !== undefined && (
              <div className="grid gap-2">
                <Label>{t('importMappings.transform.vars', 'Template variables')}</Label>
                {vars.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {t(
                      'importMappings.transform.noVars',
                      'Write variables in the template as {name}, then give each one a source path here.'
                    )}
                  </p>
                ) : (
                  vars.map((v) => (
                    <div key={v} className="flex flex-wrap items-center gap-2">
                      <code className="w-28 truncate text-sm">{`{${v}}`}</code>
                      <Input
                        className="min-w-0 flex-1"
                        value={spec.vars?.[v] ?? ''}
                        placeholder="/column"
                        aria-label={t('importMappings.transform.varPath', 'Source path of {name}', {
                          name: v,
                        })}
                        onChange={(e) => {
                          const next: Record<string, string> = {}
                          for (const name of vars) next[name] = spec.vars?.[name] ?? ''
                          next[v] = e.target.value
                          onChange({ ...spec, vars: next })
                        }}
                      />
                    </div>
                  ))
                )}
              </div>
            )}

            <div className="flex flex-wrap gap-x-6 gap-y-3">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={!!spec.first}
                  onCheckedChange={(v) => onChange(setKey(spec, 'first', v === true || undefined))}
                />
                {t('importMappings.transform.first', 'First item of a list')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={!!spec.trim}
                  onCheckedChange={(v) => onChange(setKey(spec, 'trim', v === true || undefined))}
                />
                {t('importMappings.transform.trim', 'Trim spaces')}
              </label>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor="tf-case">{t('importMappings.transform.case', 'Letter case')}</Label>
                <Select
                  value={caseValue}
                  onValueChange={(v) => {
                    const next = setKey(setKey(spec, 'lower', undefined), 'upper', undefined)
                    if (v === 'lower') next.lower = true
                    if (v === 'upper') next.upper = true
                    onChange(next)
                  }}
                >
                  <SelectTrigger id="tf-case" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">
                      {t('importMappings.transform.caseNone', 'Keep as written')}
                    </SelectItem>
                    <SelectItem value="lower">
                      {t('importMappings.transform.lower', 'lower case')}
                    </SelectItem>
                    <SelectItem value="upper">
                      {t('importMappings.transform.upper', 'UPPER CASE')}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="tf-as">{t('importMappings.transform.as', 'Convert to')}</Label>
                <Select
                  value={spec.as ?? 'none'}
                  onValueChange={(v) =>
                    onChange(
                      setKey(
                        spec,
                        'as',
                        v === 'none' ? undefined : (v as 'integer' | 'boolean' | 'string')
                      )
                    )
                  }
                >
                  <SelectTrigger id="tf-as" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">
                      {t('importMappings.transform.asNone', 'No conversion')}
                    </SelectItem>
                    <SelectItem value="integer">
                      {t('importMappings.transform.asInteger', 'Whole number')}
                    </SelectItem>
                    <SelectItem value="boolean">
                      {t('importMappings.transform.asBoolean', 'Yes or no')}
                    </SelectItem>
                    <SelectItem value="string">
                      {t('importMappings.transform.asString', 'Text')}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="tf-split">
                  {t('importMappings.transform.split', 'Split into a list at')}
                </Label>
                <Input
                  id="tf-split"
                  value={spec.split ?? ''}
                  maxLength={16}
                  placeholder={t('importMappings.transform.off', 'off')}
                  onChange={(e) =>
                    onChange(
                      setKey(spec, 'split', e.target.value === '' ? undefined : e.target.value)
                    )
                  }
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="tf-join">
                  {t('importMappings.transform.join', 'Join a list with')}
                </Label>
                <Input
                  id="tf-join"
                  value={spec.join ?? ''}
                  placeholder={t('importMappings.transform.off', 'off')}
                  onChange={(e) =>
                    onChange(
                      setKey(spec, 'join', e.target.value === '' ? undefined : e.target.value)
                    )
                  }
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="tf-max">
                  {t('importMappings.transform.maxBytes', 'Cut to at most (bytes)')}
                </Label>
                <Input
                  id="tf-max"
                  type="number"
                  inputMode="numeric"
                  min={1}
                  max={1048576}
                  value={spec.max_bytes ?? ''}
                  placeholder={t('importMappings.transform.off', 'off')}
                  onChange={(e) => {
                    const n = Number.parseInt(e.target.value, 10)
                    onChange(setKey(spec, 'max_bytes', Number.isFinite(n) && n > 0 ? n : undefined))
                  }}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="tf-default">
                  {t('importMappings.transform.default', 'Default when missing')}
                </Label>
                <Input
                  id="tf-default"
                  value={formatConst(spec.default)}
                  placeholder={t('importMappings.transform.none', 'none')}
                  onChange={(e) =>
                    onChange(
                      setKey(
                        spec,
                        'default',
                        e.target.value === ''
                          ? undefined
                          : parseConstInput(e.target.value, spec.default)
                      )
                    )
                  }
                />
              </div>
            </div>

            <div className="grid gap-2">
              <Label>{t('importMappings.transform.map', 'Value table')}</Label>
              <p className="text-xs text-muted-foreground">
                {t(
                  'importMappings.transform.mapHelp',
                  'Replace source values, such as words for severities. A value not in the table is treated as missing.'
                )}
              </p>
              {mapEntries.map(([from, to], i) => (
                <div key={i} className="flex flex-wrap items-center gap-2">
                  <Input
                    className="min-w-0 flex-1 basis-32"
                    value={from}
                    aria-label={t('importMappings.transform.mapFrom', 'Source value')}
                    onChange={(e) => {
                      const next = [...mapEntries]
                      next[i] = [e.target.value, to]
                      setMapEntries(next)
                    }}
                  />
                  <span aria-hidden className="text-muted-foreground">
                    →
                  </span>
                  <Input
                    className="min-w-0 flex-1 basis-32"
                    value={String(to)}
                    aria-label={t('importMappings.transform.mapTo', 'Becomes')}
                    onChange={(e) => {
                      const next = [...mapEntries]
                      next[i] = [from, e.target.value]
                      setMapEntries(next)
                    }}
                  />
                  {!readOnly && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      aria-label={t('importMappings.transform.mapRemove', 'Remove this value')}
                      onClick={() => setMapEntries(mapEntries.filter((_, j) => j !== i))}
                    >
                      <Trash2 className="h-4 w-4" aria-hidden />
                    </Button>
                  )}
                </div>
              ))}
              {!readOnly && (
                <div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      let key = ''
                      for (let n = 1; key === '' || key in (spec.map ?? {}); n++) key = `value${n}`
                      setMapEntries([...mapEntries, [key, '']])
                    }}
                  >
                    <Plus className="me-1 h-4 w-4" aria-hidden />
                    {t('importMappings.transform.mapAdd', 'Add a value')}
                  </Button>
                </div>
              )}
            </div>
          </fieldset>
        </DialogBody>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>
            {t('importMappings.common.done', 'Done')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
