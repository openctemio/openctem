'use client'

import { useMemo, useState } from 'react'
import {
  ArrowLeft,
  ArrowLeftRight,
  ArrowRight,
  Asterisk,
  Calendar,
  Hash,
  List,
  Lock,
  ShieldCheck,
  Sparkles,
  Trash2,
  Type,
  User,
  Wand2,
  CircleDot,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import {
  allowedDirections,
  issuesByRow,
  newRowId,
  rowFor,
  shapeOf,
  templateSnippets,
  unmappedRequired,
} from '../lib/mapping-utils'
import { renderSample } from '../lib/template-sample'
import type {
  CatalogView,
  Direction,
  FieldMeta,
  MappingRow,
  MappingSpec,
  ValidationIssue,
  SyncMode,
  Winner,
  SourceKind,
} from '../types/ticket-mapping.types'
import { TransformEditor } from './transform-editor'

interface Props {
  spec: MappingSpec
  onChange: (spec: MappingSpec) => void
  catalog: CatalogView
  fields: FieldMeta[]
  issues?: ValidationIssue[]
  readOnly: boolean
  onSuggest?: () => void
}

function FieldIcon({ field }: { field?: FieldMeta }) {
  const shape = shapeOf(field?.schema)
  const cls = 'h-3.5 w-3.5 shrink-0 text-muted-foreground'
  switch (shape) {
    case 'number':
      return <Hash className={cls} aria-hidden />
    case 'date':
      return <Calendar className={cls} aria-hidden />
    case 'user':
      return <User className={cls} aria-hidden />
    case 'labels':
    case 'options':
      return <List className={cls} aria-hidden />
    case 'option':
      return <CircleDot className={cls} aria-hidden />
  }
  return <Type className={cls} aria-hidden />
}

const DIR_ICON: Record<Direction, typeof ArrowRight> = {
  out: ArrowRight,
  in: ArrowLeft,
  both: ArrowLeftRight,
}

/** The two-column field mapper: OpenCTEM attributes on the left, the
 *  destination's Jira fields on the right; pick one of each (or drag an
 *  attribute onto a field) to connect them, then set direction, transform,
 *  sync and conflict winner per row. */
export function FieldMapper({
  spec,
  onChange,
  catalog,
  fields,
  issues,
  readOnly,
  onSuggest,
}: Props) {
  const { t } = useTranslation()
  const [attrQuery, setAttrQuery] = useState('')
  const [fieldQuery, setFieldQuery] = useState('')
  const [pickedAttr, setPickedAttr] = useState<string | null>(null)
  const [editing, setEditing] = useState<MappingRow | null>(null)

  const attrs = catalog.attributes
  const attrByPath = useMemo(() => new Map(attrs.map((a) => [a.path, a])), [attrs])
  const fieldById = useMemo(() => new Map(fields.map((f) => [f.id, f])), [fields])
  const byRow = useMemo(() => issuesByRow(issues), [issues])
  const missing = useMemo(() => unmappedRequired(spec, fields), [spec, fields])
  const mappedFields = useMemo(
    () => new Set(spec.fields.map((r) => r.target.field_id)),
    [spec.fields]
  )

  const shownAttrs = attrs.filter((a) => a.path.toLowerCase().includes(attrQuery.toLowerCase()))
  const shownFields = fields.filter(
    (f) =>
      f.name.toLowerCase().includes(fieldQuery.toLowerCase()) ||
      f.id.toLowerCase().includes(fieldQuery.toLowerCase())
  )

  const setRows = (rows: MappingRow[]) => onChange({ ...spec, fields: rows })
  const updateRow = (id: string, patch: Partial<MappingRow>) =>
    setRows(spec.fields.map((r) => (r.id === id ? { ...r, ...patch } : r)))

  const connect = (attrPath: string, field: FieldMeta) => {
    const attr = attrByPath.get(attrPath)
    if (!attr || readOnly) return
    setRows([...spec.fields, rowFor(attr, field)])
    setPickedAttr(null)
  }

  const addTemplateRow = (field?: FieldMeta) => {
    const f = field ?? fieldById.get('summary') ?? fields[0]
    if (!f) return
    setRows([
      ...spec.fields,
      {
        id: newRowId('tpl'),
        source: { kind: 'template', template: '' },
        target: { field_id: f.id, name: f.name, schema: f.schema },
        direction: 'out',
        sync: 'always',
        transform: {},
      },
    ])
  }

  return (
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6">
      {/* The two columns */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section aria-labelledby="tm-attrs" className="min-w-0 rounded-lg border">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b p-3">
            <h3 id="tm-attrs" className="text-sm font-semibold">
              {t('ticketMapping.fields.openctem', '{product} attributes')}
            </h3>
            <Input
              value={attrQuery}
              onChange={(e) => setAttrQuery(e.target.value)}
              placeholder={t('ticketMapping.common.search', 'Search')}
              aria-label={t('ticketMapping.fields.searchAttrs', 'Search attributes')}
              className="h-8 w-full sm:w-48"
            />
          </div>
          <ul
            className="max-h-80 overflow-y-auto p-2"
            role="listbox"
            aria-label={t('ticketMapping.fields.openctem', '{product} attributes')}
          >
            {shownAttrs.map((a) => (
              <li key={a.path}>
                <button
                  type="button"
                  role="option"
                  aria-selected={pickedAttr === a.path}
                  draggable={!readOnly}
                  onDragStart={(e) => e.dataTransfer.setData('text/x-openctem-attr', a.path)}
                  onClick={() => !readOnly && setPickedAttr(pickedAttr === a.path ? null : a.path)}
                  className={cn(
                    'flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-start text-sm hover:bg-muted',
                    pickedAttr === a.path && 'bg-primary/10 ring-1 ring-primary'
                  )}
                >
                  <span className="min-w-0 truncate font-mono text-xs">{a.path}</span>
                  <span className="flex shrink-0 items-center gap-1">
                    <Badge variant="outline" className="text-[10px]">
                      {t(`ticketMapping.attrType.${a.type}`, a.type)}
                    </Badge>
                    {a.inbound !== 'never' && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span>
                            <ArrowLeftRight
                              className="h-3.5 w-3.5 text-muted-foreground"
                              aria-hidden
                            />
                            <span className="sr-only">
                              {t('ticketMapping.fields.canFlowIn', 'Can flow in')}
                            </span>
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>
                          {t(`ticketMapping.inboundCap.${a.inbound}`, a.inbound)}
                        </TooltipContent>
                      </Tooltip>
                    )}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="tm-jira" className="min-w-0 rounded-lg border">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b p-3">
            <h3 id="tm-jira" className="text-sm font-semibold">
              {t('ticketMapping.fields.jira', 'Jira fields')}
            </h3>
            <Input
              value={fieldQuery}
              onChange={(e) => setFieldQuery(e.target.value)}
              placeholder={t('ticketMapping.common.search', 'Search')}
              aria-label={t('ticketMapping.fields.searchFields', 'Search Jira fields')}
              className="h-8 w-full sm:w-48"
            />
          </div>
          {pickedAttr && (
            <p className="border-b bg-primary/5 px-3 py-2 text-xs">
              {t('ticketMapping.fields.pickTarget', 'Pick the Jira field for {attr}', {
                attr: pickedAttr,
              })}
            </p>
          )}
          <ul className="max-h-80 overflow-y-auto p-2">
            {shownFields.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  disabled={readOnly}
                  onClick={() => pickedAttr && connect(pickedAttr, f)}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    const p = e.dataTransfer.getData('text/x-openctem-attr')
                    if (p) connect(p, f)
                  }}
                  className={cn(
                    'flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-start text-sm hover:bg-muted',
                    pickedAttr && 'cursor-copy',
                    missing.some((m) => m.id === f.id) && 'bg-destructive/5'
                  )}
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <FieldIcon field={f} />
                    <span className="truncate">{f.name}</span>
                    <span className="hidden truncate font-mono text-[10px] text-muted-foreground sm:inline">
                      {f.id}
                    </span>
                  </span>
                  <span className="flex shrink-0 items-center gap-1">
                    {f.required && (
                      <Badge variant="outline" className="gap-0.5 text-[10px]">
                        <Asterisk className="h-3 w-3" aria-hidden />
                        {t('ticketMapping.fields.required', 'required')}
                      </Badge>
                    )}
                    {(f.allowed_values?.length ?? 0) > 0 && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge variant="secondary" className="text-[10px]">
                            {t('ticketMapping.fields.values', '{n} values', {
                              n: f.allowed_values?.length ?? 0,
                            })}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-xs">
                          {(f.allowed_values ?? [])
                            .slice(0, 20)
                            .map((v) => v.name)
                            .join(', ')}
                        </TooltipContent>
                      </Tooltip>
                    )}
                    {mappedFields.has(f.id) && (
                      <Badge variant="default" className="text-[10px]">
                        {t('ticketMapping.fields.mapped', 'mapped')}
                      </Badge>
                    )}
                  </span>
                </button>
              </li>
            ))}
            {shownFields.length === 0 && (
              <li className="p-3 text-sm text-muted-foreground">
                {t('ticketMapping.fields.noFields', 'No fields (the Jira site could not be read).')}
              </li>
            )}
          </ul>
        </section>
      </div>

      {missing.length > 0 && (
        <div
          className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm"
          role="status"
        >
          {t(
            'ticketMapping.fields.missingRequired',
            'Required Jira fields without a mapping: {names}',
            {
              names: missing.map((m) => m.name).join(', '),
            }
          )}
        </div>
      )}

      {/* The rows */}
      <section aria-labelledby="tm-rows">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h3 id="tm-rows" className="text-sm font-semibold">
            {t('ticketMapping.fields.rows', 'Mappings ({n})', { n: spec.fields.length })}
          </h3>
          {!readOnly && (
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => addTemplateRow()}>
                <Wand2 className="me-1 h-4 w-4" aria-hidden />
                {t('ticketMapping.fields.addTemplate', 'Template row')}
              </Button>
              {onSuggest && (
                <Button variant="outline" size="sm" onClick={onSuggest}>
                  <Sparkles className="me-1 h-4 w-4" aria-hidden />
                  {t('ticketMapping.fields.suggest', 'Suggest')}
                </Button>
              )}
            </div>
          )}
        </div>
        {spec.fields.length === 0 ? (
          <p className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
            {t(
              'ticketMapping.fields.noRows',
              'Pick an attribute on the left and a Jira field on the right, or drag one onto the other.'
            )}
          </p>
        ) : (
          <ul className="grid gap-2">
            {spec.fields.map((r) => (
              <MappingRowCard
                key={r.id}
                row={r}
                catalog={catalog}
                fields={fields}
                issues={byRow.get(r.id)}
                readOnly={readOnly}
                onChange={(patch) => updateRow(r.id, patch)}
                onRemove={() => setRows(spec.fields.filter((x) => x.id !== r.id))}
                onEditTransform={() => setEditing(r)}
              />
            ))}
          </ul>
        )}
      </section>

      {editing && (
        <TransformEditor
          open
          onOpenChange={(o) => !o && setEditing(null)}
          row={editing}
          attr={editing.source.attr ? attrByPath.get(editing.source.attr) : undefined}
          field={fieldById.get(editing.target.field_id)}
          transformKinds={catalog.transform_kinds}
          onSave={(tr) => updateRow(editing.id, { transform: tr })}
        />
      )}
    </div>
  )
}

interface RowProps {
  row: MappingRow
  catalog: CatalogView
  fields: FieldMeta[]
  issues?: ValidationIssue[]
  readOnly: boolean
  onChange: (patch: Partial<MappingRow>) => void
  onRemove: () => void
  onEditTransform: () => void
}

function MappingRowCard({
  row,
  catalog,
  fields,
  issues,
  readOnly,
  onChange,
  onRemove,
  onEditTransform,
}: RowProps) {
  const { t } = useTranslation()
  const attr = row.source.attr
    ? catalog.attributes.find((a) => a.path === row.source.attr)
    : undefined
  const dirs = allowedDirections(row, attr)
  const field = fields.find((f) => f.id === row.target.field_id)
  const hasError = issues?.some((i) => i.severity === 'error')
  const sample =
    row.source.kind === 'template'
      ? renderSample(row.source.template ?? '', catalog.attributes, catalog.filters)
      : null

  const setSourceKind = (k: SourceKind) =>
    onChange({
      source:
        k === 'attr'
          ? { kind: 'attr', attr: catalog.attributes[0]?.path }
          : k === 'template'
            ? { kind: 'template', template: '' }
            : { kind: 'const', value: '' },
      direction: 'out',
    })

  return (
    <li className={cn('rounded-lg border p-3', hasError && 'border-destructive')}>
      <div className="grid items-center gap-2 md:grid-cols-[minmax(0,1.3fr)_auto_minmax(0,1fr)_auto]">
        {/* Source */}
        <div className="flex min-w-0 gap-2">
          <Select
            value={row.source.kind}
            onValueChange={(v) => setSourceKind(v as SourceKind)}
            disabled={readOnly}
          >
            <SelectTrigger
              className="h-8 w-28 shrink-0"
              aria-label={t('ticketMapping.fields.sourceKind', 'Source kind')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="attr">{t('ticketMapping.source.attr', 'Attribute')}</SelectItem>
              <SelectItem value="template">
                {t('ticketMapping.source.template', 'Template')}
              </SelectItem>
              <SelectItem value="const">{t('ticketMapping.source.const', 'Constant')}</SelectItem>
            </SelectContent>
          </Select>
          {row.source.kind === 'attr' && (
            <Select
              value={row.source.attr}
              onValueChange={(v) => onChange({ source: { kind: 'attr', attr: v } })}
              disabled={readOnly}
            >
              <SelectTrigger
                className="h-8 min-w-0 font-mono text-xs"
                aria-label={t('ticketMapping.fields.attribute', 'Attribute')}
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {catalog.attributes.map((a) => (
                  <SelectItem key={a.path} value={a.path} className="font-mono text-xs">
                    {a.path}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          {row.source.kind === 'const' && (
            <Input
              className="h-8"
              value={row.source.value ?? ''}
              maxLength={1000}
              disabled={readOnly}
              aria-label={t('ticketMapping.source.const', 'Constant')}
              onChange={(e) => onChange({ source: { kind: 'const', value: e.target.value } })}
            />
          )}
          {row.source.kind === 'template' && (
            <span className="truncate text-xs text-muted-foreground">
              {t('ticketMapping.fields.templateBelow', 'template below')}
            </span>
          )}
        </div>

        {/* Direction */}
        <div
          className="flex shrink-0 items-center rounded-md border p-0.5"
          role="radiogroup"
          aria-label={t('ticketMapping.fields.direction', 'Direction')}
        >
          {(['out', 'in', 'both'] as Direction[]).map((d) => {
            const Icon = DIR_ICON[d]
            const allowed = dirs.includes(d)
            return (
              <Tooltip key={d}>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    role="radio"
                    aria-checked={row.direction === d}
                    aria-label={t(`ticketMapping.direction.${d}`, d)}
                    disabled={readOnly || !allowed}
                    onClick={() =>
                      onChange({
                        direction: d,
                        winner: d === 'both' ? (row.winner ?? 'openctem') : row.winner,
                      })
                    }
                    className={cn(
                      'rounded p-1.5 disabled:opacity-40',
                      row.direction === d ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
                    )}
                  >
                    {allowed ? (
                      <Icon className="h-4 w-4" aria-hidden />
                    ) : (
                      <Lock className="h-4 w-4" aria-hidden />
                    )}
                  </button>
                </TooltipTrigger>
                <TooltipContent>
                  {allowed
                    ? t(`ticketMapping.direction.${d}`, d)
                    : t(
                        'ticketMapping.direction.locked',
                        'This attribute is never changed from Jira'
                      )}
                </TooltipContent>
              </Tooltip>
            )
          })}
        </div>

        {/* Target */}
        <Select
          value={row.target.field_id}
          disabled={readOnly}
          onValueChange={(v) => {
            const f = fields.find((x) => x.id === v)
            if (f) onChange({ target: { field_id: f.id, name: f.name, schema: f.schema } })
          }}
        >
          <SelectTrigger
            className="h-8 min-w-0"
            aria-label={t('ticketMapping.fields.target', 'Jira field')}
          >
            <span className="flex min-w-0 items-center gap-2">
              <FieldIcon field={field} />
              <span className="truncate">
                {field?.name ?? row.target.name ?? row.target.field_id}
              </span>
            </span>
          </SelectTrigger>
          <SelectContent>
            {fields.map((f) => (
              <SelectItem key={f.id} value={f.id}>
                {f.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {/* Row actions */}
        <div className="flex shrink-0 items-center gap-1">
          <Button
            variant="outline"
            size="sm"
            onClick={onEditTransform}
            disabled={readOnly || row.source.kind === 'template'}
          >
            {t(
              `ticketMapping.transformKind.${row.transform?.kind || 'none'}`,
              row.transform?.kind || 'none'
            )}
          </Button>
          {!readOnly && (
            <Button
              variant="ghost"
              size="icon"
              aria-label={t('ticketMapping.common.remove', 'Remove')}
              onClick={onRemove}
            >
              <Trash2 className="h-4 w-4" aria-hidden />
            </Button>
          )}
        </div>
      </div>

      {row.source.kind === 'template' && (
        <div className="mt-2 grid gap-2">
          <Textarea
            value={row.source.template ?? ''}
            maxLength={4000}
            rows={row.target.field_id === 'description' ? 5 : 2}
            disabled={readOnly}
            className="font-mono text-xs"
            aria-label={t('ticketMapping.source.template', 'Template')}
            onChange={(e) => onChange({ source: { kind: 'template', template: e.target.value } })}
          />
          {!readOnly && (
            <div
              className="flex flex-wrap gap-1"
              aria-label={t('ticketMapping.fields.insert', 'Insert')}
            >
              {templateSnippets(catalog.attributes)
                .slice(0, 40)
                .map((s) => (
                  <button
                    key={s}
                    type="button"
                    className="rounded border px-1.5 py-0.5 font-mono text-[10px] hover:bg-muted"
                    onClick={() =>
                      onChange({
                        source: { kind: 'template', template: `${row.source.template ?? ''}${s}` },
                      })
                    }
                  >
                    {s.replace(/^\{\{ | \}\}$/g, '')}
                  </button>
                ))}
            </div>
          )}
          {sample && (
            <div className="rounded-md bg-muted/50 p-2 text-xs">
              <span className="font-medium">{t('ticketMapping.fields.sample', 'Sample')}: </span>
              <span className="whitespace-pre-wrap">{sample.text}</span>
              {sample.errors.length > 0 && (
                <p className="mt-1 text-destructive">
                  {t('ticketMapping.fields.unknownInTemplate', 'Unknown: {names}', {
                    names: sample.errors.join(', '),
                  })}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
        <Select
          value={row.sync ?? 'always'}
          onValueChange={(v) => onChange({ sync: v as SyncMode })}
          disabled={readOnly}
        >
          <SelectTrigger
            className="h-7 w-auto text-xs"
            aria-label={t('ticketMapping.fields.sync', 'When')}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="create">
              {t('ticketMapping.sync.create', 'On create only')}
            </SelectItem>
            <SelectItem value="always">{t('ticketMapping.sync.always', 'Always')}</SelectItem>
            <SelectItem value="preserve_edits">
              {t('ticketMapping.sync.preserve_edits', 'Keep edits made in Jira')}
            </SelectItem>
          </SelectContent>
        </Select>
        {row.direction === 'both' && (
          <Select
            value={row.winner ?? 'openctem'}
            onValueChange={(v) => onChange({ winner: v as Winner })}
            disabled={readOnly}
          >
            <SelectTrigger
              className="h-7 w-auto text-xs"
              aria-label={t('ticketMapping.fields.winner', 'On conflict')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="openctem">
                {t('ticketMapping.winner.openctem', '{product} wins')}
              </SelectItem>
              <SelectItem value="tracker">
                {t('ticketMapping.winner.tracker', 'Jira wins')}
              </SelectItem>
              <SelectItem value="last_writer">
                {t('ticketMapping.winner.last_writer', 'Last change wins')}
              </SelectItem>
            </SelectContent>
          </Select>
        )}
        {attr && row.direction !== 'out' && attr.inbound === 'request' && (
          <Badge variant="secondary" className="gap-1">
            <Lock className="h-3 w-3" aria-hidden />
            {t(
              'ticketMapping.inboundCap.request',
              'A change from Jira becomes a request a person decides'
            )}
          </Badge>
        )}
        {(issues ?? []).map((i, idx) => (
          <span
            key={idx}
            className={cn(
              'rounded px-1.5 py-0.5',
              i.severity === 'error'
                ? 'bg-destructive/10 text-destructive'
                : 'bg-warning/10 text-warning'
            )}
          >
            {i.message}
          </span>
        ))}
      </div>
    </li>
  )
}

export function MappingSettingsBar({
  spec,
  onChange,
  readOnly,
}: {
  spec: MappingSpec
  onChange: (s: MappingSpec) => void
  readOnly: boolean
}) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border p-3 text-sm">
      <label className="flex items-center gap-2">
        <span className="text-muted-foreground">
          {t('ticketMapping.settings.dataLevel', 'Data sent')}
        </span>
        <Select
          value={spec.minimization}
          onValueChange={(v) =>
            onChange({ ...spec, minimization: v as MappingSpec['minimization'] })
          }
          disabled={readOnly}
        >
          <SelectTrigger className="h-8 w-auto">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="title_only">
              {t('ticketMapping.minimization.title_only', 'Title only')}
            </SelectItem>
            <SelectItem value="summary">
              {t('ticketMapping.minimization.summary', 'Summary')}
            </SelectItem>
            <SelectItem value="full">{t('ticketMapping.minimization.full', 'Full')}</SelectItem>
          </SelectContent>
        </Select>
      </label>
      <label className="flex items-center gap-2">
        <Switch
          checked={spec.comments_out}
          disabled={readOnly}
          onCheckedChange={(v) => onChange({ ...spec, comments_out: v })}
        />
        {t('ticketMapping.settings.commentsOut', 'Post verification results as comments')}
      </label>
      <label className="flex items-center gap-2">
        <Switch
          checked={spec.comments_in}
          disabled={readOnly}
          onCheckedChange={(v) => onChange({ ...spec, comments_in: v })}
        />
        {t('ticketMapping.settings.commentsIn', 'Import Jira comments to the timeline')}
      </label>
      <span className="text-xs text-muted-foreground">
        <ShieldCheck className="me-1 inline h-3 w-3" aria-hidden />
        {t('ticketMapping.settings.redaction', 'Secrets are always removed after rendering.')}
      </span>
    </div>
  )
}
