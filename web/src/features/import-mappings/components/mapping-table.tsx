'use client'

import { useState } from 'react'
import { Plus, SlidersHorizontal, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import {
  activeTransforms,
  formatConst,
  newRow,
  newRule,
  parseConstInput,
  renameTarget,
  sourceKindOf,
  toggleIdentity,
  withSourceKind,
  type DraftRule,
  type MappingDraft,
  type MappingRow,
  type SourceKind,
} from '../lib/mapping-model'
import { isIdentityEligible, targetsFor } from '../lib/targets'
import type { Predicate, RuleKind, ValueSpecObject } from '../types/import-mapping.types'
import { TransformDialog } from './transform-dialog'

const CUSTOM = '__custom__'

interface MappingTableProps {
  draft: MappingDraft
  onChange: (draft: MappingDraft) => void
  /** Source fields seen in the sample (from the preview), as paths. */
  fields: string[]
  readOnly: boolean
}

type Translate = ReturnType<typeof useTranslation>['t']

function predicateText(t: Translate, p: Predicate): string {
  if (p.exists !== undefined)
    return p.exists
      ? t('importMappings.table.exists', '{path} is present', { path: p.path })
      : t('importMappings.table.missing', '{path} is missing', { path: p.path })
  if (p.equals !== undefined) return `${p.path} = ${String(p.equals)}`
  if (p.in !== undefined) return `${p.path} in [${p.in.map(String).join(', ')}]`
  if (p.matches !== undefined) return `${p.path} ~ ${p.matches}`
  return p.path
}

/** A source path: a column from the sample, or any path typed by hand. */
function SourcePathInput({
  value,
  fields,
  onChange,
  readOnly,
  label,
}: {
  value: string
  fields: string[]
  onChange: (v: string) => void
  readOnly: boolean
  label: string
}) {
  const { t } = useTranslation()
  const [custom, setCustom] = useState(false)
  const pick = fields.length > 0 && !custom && (value === '' || fields.includes(value))
  if (pick) {
    return (
      <Select
        value={value || undefined}
        onValueChange={(v) => (v === CUSTOM ? setCustom(true) : onChange(v))}
        disabled={readOnly}
      >
        <SelectTrigger className="w-full min-w-0" aria-label={label}>
          <SelectValue placeholder={t('importMappings.table.pickColumn', 'Pick a column')} />
        </SelectTrigger>
        <SelectContent>
          {fields.map((f) => (
            <SelectItem key={f} value={f}>
              {f}
            </SelectItem>
          ))}
          <SelectItem value={CUSTOM}>
            {t('importMappings.table.customPath', 'Type a path…')}
          </SelectItem>
        </SelectContent>
      </Select>
    )
  }
  return (
    <div className="flex min-w-0 items-center gap-1">
      <Input
        className="min-w-0 flex-1 font-mono text-xs"
        value={value}
        placeholder="/column"
        aria-label={label}
        readOnly={readOnly}
        onChange={(e) => onChange(e.target.value)}
      />
      {fields.length > 0 && !readOnly && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => {
            setCustom(false)
            if (!fields.includes(value)) onChange('')
          }}
        >
          {t('importMappings.table.columns', 'Columns')}
        </Button>
      )}
    </div>
  )
}

function RowEditor({
  rule,
  row,
  draft,
  onChange,
  fields,
  readOnly,
}: {
  rule: DraftRule
  row: MappingRow
  draft: MappingDraft
  onChange: (draft: MappingDraft) => void
  fields: string[]
  readOnly: boolean
}) {
  const { t } = useTranslation()
  const [transformsOpen, setTransformsOpen] = useState(false)
  const options = targetsFor(rule.kind)
  const known = options.includes(row.target)
  const taken = new Set(rule.rows.filter((r) => r.key !== row.key).map((r) => r.target))
  const kind = sourceKindOf(row.spec)
  const transforms = activeTransforms(row.spec)
  const identityOk = rule.kind === 'finding' && isIdentityEligible(row.target)
  const targetLabel = row.target || t('importMappings.table.noTarget', 'new row')

  const setSpec = (spec: ValueSpecObject) =>
    onChange({
      ...draft,
      rules: draft.rules.map((r) =>
        r.key !== rule.key
          ? r
          : { ...r, rows: r.rows.map((x) => (x.key === row.key ? { ...x, spec } : x)) }
      ),
    })

  const remove = () => {
    const next = {
      ...draft,
      rules: draft.rules.map((r) =>
        r.key !== rule.key ? r : { ...r, rows: r.rows.filter((x) => x.key !== row.key) }
      ),
    }
    const stillSet = next.rules.some(
      (r) => r.kind === 'finding' && r.rows.some((x) => x.target === row.target)
    )
    onChange(stillSet ? next : toggleIdentity(next, row.target, false))
  }

  return (
    <li className="grid gap-2 border-b border-border/60 py-3 last:border-b-0">
      <div className="flex flex-wrap items-center gap-2">
        <div className="w-full min-w-0 sm:w-48">
          {known || !row.target ? (
            <Select
              value={row.target || undefined}
              onValueChange={(v) => onChange(renameTarget(draft, rule.key, row.key, v))}
              disabled={readOnly || options.length === 0}
            >
              <SelectTrigger
                className="w-full min-w-0"
                aria-label={t('importMappings.table.target', 'Field')}
              >
                <SelectValue placeholder={t('importMappings.table.pickField', 'Pick a field')} />
              </SelectTrigger>
              <SelectContent>
                {options.map((o) => (
                  <SelectItem key={o} value={o} disabled={taken.has(o)}>
                    {o}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <code
              className="block truncate rounded-md border px-3 py-2 text-xs"
              title={t('importMappings.table.otherTarget', 'Set in the JSON document')}
            >
              {row.target}
            </code>
          )}
        </div>

        <div className="flex min-w-0 flex-1 basis-60 items-center gap-2">
          <Select
            value={kind}
            onValueChange={(v) => setSpec(withSourceKind(row.spec, v as SourceKind))}
            disabled={readOnly}
          >
            <SelectTrigger
              className="w-28 shrink-0"
              aria-label={t('importMappings.table.sourceKind', 'Source of {target}', {
                target: targetLabel,
              })}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="path">{t('importMappings.table.kindPath', 'Column')}</SelectItem>
              <SelectItem value="const">
                {t('importMappings.table.kindConst', 'Constant')}
              </SelectItem>
              <SelectItem value="template">
                {t('importMappings.table.kindTemplate', 'Template')}
              </SelectItem>
            </SelectContent>
          </Select>
          <div className="min-w-0 flex-1">
            {kind === 'path' ? (
              <SourcePathInput
                value={row.spec.path ?? ''}
                fields={fields}
                readOnly={readOnly}
                label={t('importMappings.table.sourcePath', 'Column for {target}', {
                  target: targetLabel,
                })}
                onChange={(path) => setSpec({ ...row.spec, path })}
              />
            ) : kind === 'const' ? (
              <Input
                value={formatConst(row.spec.const)}
                readOnly={readOnly}
                aria-label={t('importMappings.table.constValue', 'Constant for {target}', {
                  target: targetLabel,
                })}
                onChange={(e) =>
                  setSpec({ ...row.spec, const: parseConstInput(e.target.value, row.spec.const) })
                }
              />
            ) : (
              <Input
                className="font-mono text-xs"
                value={row.spec.template ?? ''}
                placeholder="{host}:{port}"
                readOnly={readOnly}
                aria-label={t('importMappings.table.templateValue', 'Template for {target}', {
                  target: targetLabel,
                })}
                onChange={(e) => setSpec({ ...row.spec, template: e.target.value })}
              />
            )}
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setTransformsOpen(true)}
          aria-label={t('importMappings.table.transformsFor', 'Transforms for {target}', {
            target: targetLabel,
          })}
        >
          <SlidersHorizontal className="me-1 h-4 w-4" aria-hidden />
          {transforms.length > 0
            ? t('importMappings.table.transformCount', 'Transforms ({count})', {
                count: transforms.length,
              })
            : kind === 'template'
              ? t('importMappings.table.variables', 'Variables')
              : t('importMappings.table.transforms', 'Transforms')}
        </Button>
        {identityOk ? (
          <label className="flex items-center gap-1.5 text-sm">
            <Checkbox
              checked={draft.identity.includes(row.target)}
              disabled={readOnly}
              onCheckedChange={(v) => onChange(toggleIdentity(draft, row.target, v === true))}
              aria-label={t(
                'importMappings.table.identityFor',
                'Use {target} to identify a finding',
                {
                  target: row.target,
                }
              )}
            />
            {t('importMappings.table.identity', 'Identity')}
          </label>
        ) : null}
        {transforms.map((name) => (
          <Badge key={name} variant="secondary" className="font-normal">
            {t(`importMappings.transformName.${name}`, name)}
          </Badge>
        ))}
        {!readOnly && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="ms-auto"
            onClick={remove}
            aria-label={t('importMappings.table.removeRow', 'Remove {target}', {
              target: targetLabel,
            })}
          >
            <Trash2 className="h-4 w-4" aria-hidden />
          </Button>
        )}
      </div>
      <TransformDialog
        open={transformsOpen}
        onOpenChange={setTransformsOpen}
        target={row.target}
        spec={row.spec}
        onChange={setSpec}
        readOnly={readOnly}
      />
    </li>
  )
}

/** One row per CTIS target of each rule, with its source, transforms and identity. */
export function MappingTable({ draft, onChange, fields, readOnly }: MappingTableProps) {
  const { t } = useTranslation()

  const updateRule = (key: string, fn: (r: DraftRule) => DraftRule) =>
    onChange({ ...draft, rules: draft.rules.map((r) => (r.key === key ? fn(r) : r)) })

  const removeRule = (key: string) => {
    const rules = draft.rules.filter((r) => r.key !== key)
    const hasFinding = rules.some((r) => r.kind === 'finding')
    onChange({ ...draft, rules, identity: hasFinding ? draft.identity : [] })
  }

  return (
    <div className="grid gap-4">
      {draft.rules.map((rule, i) => {
        const conditions =
          rule.when === undefined ? [] : Array.isArray(rule.when) ? rule.when : [rule.when]
        return (
          <section
            key={rule.key}
            className="min-w-0 rounded-lg border bg-card p-3"
            aria-label={t('importMappings.table.ruleN', 'Rule {n}', { n: i + 1 })}
          >
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-medium">
                {t('importMappings.table.ruleN', 'Rule {n}', { n: i + 1 })}
              </h3>
              {rule.kind === 'dependency' ? (
                <Badge variant="outline">{t('importMappings.kind.dependency', 'Dependency')}</Badge>
              ) : (
                <Select
                  value={rule.kind}
                  disabled={readOnly}
                  onValueChange={(v) => {
                    const kind = v as RuleKind
                    const allowed = targetsFor(kind)
                    updateRule(rule.key, (r) => ({
                      ...r,
                      kind,
                      rows: r.rows.filter((row) => !row.target || allowed.includes(row.target)),
                    }))
                  }}
                >
                  <SelectTrigger
                    className="h-8 w-36"
                    aria-label={t('importMappings.table.ruleKind', 'What rule {n} creates', {
                      n: i + 1,
                    })}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="finding">
                      {t('importMappings.kind.finding', 'Finding')}
                    </SelectItem>
                    <SelectItem value="asset">{t('importMappings.kind.asset', 'Asset')}</SelectItem>
                  </SelectContent>
                </Select>
              )}
              <div className="ms-auto">
                {!readOnly && draft.rules.length > 1 && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => removeRule(rule.key)}
                  >
                    <Trash2 className="me-1 h-4 w-4" aria-hidden />
                    {t('importMappings.table.removeRule', 'Remove rule')}
                  </Button>
                )}
              </div>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {conditions.length === 0
                ? t('importMappings.table.always', 'Applies to every record.')
                : t(
                    'importMappings.table.when',
                    'Applies when: {conditions}. Edit conditions in the JSON document.',
                    { conditions: conditions.map((c) => predicateText(t, c)).join('; ') }
                  )}
            </p>
            <ul className="mt-2">
              {rule.rows.map((row) => (
                <RowEditor
                  key={row.key}
                  rule={rule}
                  row={row}
                  draft={draft}
                  onChange={onChange}
                  fields={fields}
                  readOnly={readOnly}
                />
              ))}
            </ul>
            {!readOnly && rule.kind !== 'dependency' && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-2"
                onClick={() => updateRule(rule.key, (r) => ({ ...r, rows: [...r.rows, newRow()] }))}
              >
                <Plus className="me-1 h-4 w-4" aria-hidden />
                {t('importMappings.table.addRow', 'Add a field')}
              </Button>
            )}
          </section>
        )
      })}
      {!readOnly && (
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onChange({ ...draft, rules: [...draft.rules, newRule('finding')] })}
          >
            <Plus className="me-1 h-4 w-4" aria-hidden />
            {t('importMappings.table.addFindingRule', 'Add a finding rule')}
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onChange({ ...draft, rules: [...draft.rules, newRule('asset')] })}
          >
            <Plus className="me-1 h-4 w-4" aria-hidden />
            {t('importMappings.table.addAssetRule', 'Add an asset rule')}
          </Button>
        </div>
      )}
    </div>
  )
}
