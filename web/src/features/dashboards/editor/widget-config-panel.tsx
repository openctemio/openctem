'use client'

/**
 * Configure one widget: what it counts (metric, filters, group-by), the time
 * window, how it is drawn (only visualizations valid for the result shape),
 * a target for single figures, and its title. A live preview from the
 * viewer's own data sits on top; nothing is saved until the dashboard is.
 */

import { useEffect, useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
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
  Sheet,
  SheetBody,
  SheetContent,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { unitOf } from '../api/widget-adapter'
import { previewWidget, type WidgetValue } from '../api/widget-data'
import {
  useWidgetCatalog,
  vizzesFor,
  type CatalogMetric,
  type Dimension,
  type WidgetFilter,
  type WidgetSpec,
} from '../api/widget-spec'
import { WidgetView } from '../components/widget-view'
import { dimensionNameKey, dimensionValueKey, metricNameKey } from '../metrics'
import {
  NOTE_MAX_LENGTH,
  TITLE_MAX_LENGTH,
  newMetricSpec,
  specShape,
  takesTarget,
  takesTime,
  withFilter,
  withGroupBy,
  withMetric,
  withViz,
} from './spec-ops'

const NONE = '__none'
const ANY = '__any'
/** Wait this long after the last change before asking for a preview. */
export const PREVIEW_DEBOUNCE_MS = 500

export interface WidgetConfigPanelProps {
  /** The spec being edited; null closes the panel. */
  spec: WidgetSpec | null
  /**
   * The figures already known for `spec` (a gallery preview or the stored
   * value). While the draft is unchanged they stand in for a preview request.
   */
  initialValue?: WidgetValue
  onCancel: () => void
  onApply: (spec: WidgetSpec, preview?: WidgetValue) => void
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <fieldset className="flex flex-col gap-3 border-t pt-3 first:border-t-0 first:pt-0">
      <legend className="text-sm font-medium">{title}</legend>
      {children}
    </fieldset>
  )
}

function filterKey(dim: Dimension): keyof WidgetFilter {
  return dim === 'asset_group' ? 'asset_group_id' : (dim as keyof WidgetFilter)
}

/** Value chips of one list dimension (toggle buttons, keyboard accessible). */
function ChipFilter({
  dim,
  values,
  selected,
  onChange,
}: {
  dim: Dimension
  values: string[]
  selected: string[]
  onChange: (next: string[]) => void
}) {
  const { t } = useTranslation()
  return (
    <div role="group" aria-label={t(dimensionNameKey(dim), dim)} className="flex flex-wrap gap-1.5">
      {values.map((v) => {
        const on = selected.includes(v)
        return (
          <button
            key={v}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(on ? selected.filter((x) => x !== v) : [...selected, v])}
            className={cn(
              'rounded-full border px-2.5 py-0.5 text-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
              on ? 'border-primary bg-primary/10 text-foreground' : 'text-muted-foreground'
            )}
          >
            {t(dimensionValueKey(dim, v), v)}
          </button>
        )
      })}
    </div>
  )
}

function previewKeyOf(spec: WidgetSpec | null): string {
  return spec && spec.data.kind !== 'note' ? JSON.stringify({ ...spec, title: undefined }) : ''
}

export function WidgetConfigPanel({
  spec,
  initialValue,
  onCancel,
  onApply,
}: WidgetConfigPanelProps) {
  const { t } = useTranslation()
  const catalog = useWidgetCatalog()
  const [draft, setDraft] = useState<WidgetSpec | null>(spec)
  // The figures, with the draft (preview key) they were computed for.
  const [previewed, setPreviewed] = useState<{ key: string; value: WidgetValue } | undefined>()
  // The target text while it is being edited; null shows the draft's value.
  const [targetText, setTargetText] = useState<string | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const [previewFailed, setPreviewFailed] = useState(false)

  useEffect(() => {
    setDraft(spec)
    setTargetText(null)
    setPreviewed(initialValue ? { key: previewKeyOf(spec), value: initialValue } : undefined)
    // initialValue belongs to spec: it is read when a new spec is opened.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [spec])
  const initialKey = initialValue ? previewKeyOf(spec) : ''

  const metrics = useMemo(() => catalog.data?.metrics ?? [], [catalog.data])
  const metric: CatalogMetric | undefined = metrics.find((m) => m.id === draft?.data.metric)
  const isNote = draft?.data.kind === 'note'

  // Live preview of a metric widget, debounced; a stale answer is dropped.
  const previewKey = previewKeyOf(draft)
  // Only a preview computed for the current draft is shown or applied.
  const preview = previewed?.value
  const freshPreview = previewed?.key === previewKey ? previewed.value : undefined
  useEffect(() => {
    if (!previewKey) return
    // The draft still matches a value we already hold: no request.
    if (previewKey === initialKey && initialValue) {
      setPreviewed({ key: previewKey, value: initialValue })
      setPreviewing(false)
      setPreviewFailed(false)
      return
    }
    let live = true
    setPreviewing(true)
    const timer = setTimeout(() => {
      previewWidget('metric', JSON.parse(previewKey))
        .then((v) => {
          if (!live) return
          setPreviewed({ key: previewKey, value: v })
          setPreviewFailed(false)
        })
        .catch(() => live && setPreviewFailed(true))
        .finally(() => live && setPreviewing(false))
    }, PREVIEW_DEBOUNCE_MS)
    return () => {
      live = false
      clearTimeout(timer)
    }
    // initialValue and initialKey change only with a new spec.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewKey])

  const open = spec !== null && draft !== null
  const groupBy = draft?.data.group_by ?? []
  const noteText = draft?.data.text ?? ''
  const unit = draft
    ? unitOf({ shape: specShape(draft, metric), metric: draft.data.metric } as WidgetValue)
    : 'count'
  const targetMax = unit === 'percent' ? 100 : undefined
  // An empty target value is "no value": it is never stored as 0.
  const targetNumber = targetText === null ? undefined : Number(targetText)
  const targetEmpty =
    !!draft?.target &&
    targetText !== null &&
    (targetText.trim() === '' ||
      !Number.isFinite(targetNumber) ||
      (targetNumber as number) < 0 ||
      (targetMax !== undefined && (targetNumber as number) > targetMax))
  const canApply =
    !!draft &&
    !targetEmpty &&
    (isNote ? noteText.trim().length > 0 && noteText.length <= NOTE_MAX_LENGTH : !!metric)

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onCancel()}>
      <SheetContent side="right" className="w-full sm:max-w-[32rem]">
        <SheetHeader>
          <SheetTitle>
            {isNote
              ? t('dashboards.config.titleNote', 'Configure note')
              : t('dashboards.config.title', 'Configure widget')}
          </SheetTitle>
        </SheetHeader>
        {draft && (
          <SheetBody>
            <div className="flex flex-col gap-4">
              {!isNote && (
                <div aria-live="polite" aria-busy={previewing}>
                  {previewFailed && !preview ? (
                    <p className="text-xs text-muted-foreground">
                      {t('dashboards.config.previewFailed', 'No preview right now.')}
                    </p>
                  ) : (
                    <WidgetView
                      widget={{
                        widget_type: 'metric',
                        config: draft as unknown as Record<string, unknown>,
                      }}
                      value={preview}
                      loading={!preview}
                    />
                  )}
                </div>
              )}

              {isNote ? (
                <Section title={t('dashboards.config.note', 'Text')}>
                  <Label htmlFor="widget-note-text" className="sr-only">
                    {t('dashboards.config.note', 'Text')}
                  </Label>
                  <Textarea
                    id="widget-note-text"
                    value={noteText}
                    maxLength={NOTE_MAX_LENGTH}
                    rows={8}
                    onChange={(e) =>
                      setDraft({ ...draft, data: { ...draft.data, text: e.target.value } })
                    }
                    placeholder={t('dashboards.config.notePlaceholder', 'Markdown is supported.')}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t('dashboards.config.noteCount', '{n} of {max} characters', {
                      n: noteText.length,
                      max: NOTE_MAX_LENGTH,
                    })}
                  </p>
                </Section>
              ) : (
                <>
                  <Section title={t('dashboards.config.data', 'Data')}>
                    <div className="flex flex-col gap-1.5">
                      <Label htmlFor="widget-metric">
                        {t('dashboards.config.metric', 'Metric')}
                      </Label>
                      <Select
                        value={draft.data.metric}
                        onValueChange={(id) => {
                          const m = metrics.find((x) => x.id === id)
                          if (m) setDraft(withMetric(draft, m))
                        }}
                      >
                        <SelectTrigger id="widget-metric">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {metrics.map((m) => (
                            <SelectItem key={m.id} value={m.id}>
                              {t(metricNameKey(m.id), m.id)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    {metric?.filters
                      .filter((d) => d !== 'asset_group')
                      .map((dim) => {
                        const key = filterKey(dim)
                        const current = draft.data.filter?.[key]
                        if (dim === 'kev' || dim === 'reachable') {
                          const v = current === true ? 'true' : current === false ? 'false' : ANY
                          return (
                            <div key={dim} className="flex flex-col gap-1.5">
                              <Label htmlFor={`widget-filter-${dim}`}>
                                {t(dimensionNameKey(dim), dim)}
                              </Label>
                              <Select
                                value={v}
                                onValueChange={(x) =>
                                  setDraft(
                                    withFilter(draft, key, x === ANY ? undefined : x === 'true')
                                  )
                                }
                              >
                                <SelectTrigger id={`widget-filter-${dim}`}>
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value={ANY}>
                                    {t('dashboards.config.any', 'Any')}
                                  </SelectItem>
                                  <SelectItem value="true">
                                    {t(dimensionValueKey(dim, 'true'), 'Yes')}
                                  </SelectItem>
                                  <SelectItem value="false">
                                    {t(dimensionValueKey(dim, 'false'), 'No')}
                                  </SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                          )
                        }
                        const values = catalog.data?.dimensions[dim] ?? []
                        if (values.length === 0) return null
                        return (
                          <div key={dim} className="flex flex-col gap-1.5">
                            <span className="text-sm font-medium">
                              {t(dimensionNameKey(dim), dim)}
                            </span>
                            <ChipFilter
                              dim={dim}
                              values={values}
                              selected={Array.isArray(current) ? current : []}
                              onChange={(next) => setDraft(withFilter(draft, key, next))}
                            />
                          </div>
                        )
                      })}
                    {metric &&
                      metric.max_group_by > 0 &&
                      Array.from({ length: metric.max_group_by }, (_, i) => (
                        <div key={i} className="flex flex-col gap-1.5">
                          <Label htmlFor={`widget-groupby-${i}`}>
                            {i === 0
                              ? t('dashboards.config.groupBy', 'Group by')
                              : t('dashboards.config.thenBy', 'Then by')}
                          </Label>
                          <Select
                            value={groupBy[i] ?? NONE}
                            disabled={i > groupBy.length}
                            onValueChange={(d) => {
                              const next = [...groupBy]
                              if (d === NONE) next.splice(i)
                              else next[i] = d as Dimension
                              setDraft(withGroupBy(draft, metric, next))
                            }}
                          >
                            <SelectTrigger id={`widget-groupby-${i}`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value={NONE}>
                                {t('dashboards.config.noGroup', 'None')}
                              </SelectItem>
                              {metric.group_bys
                                .filter((d) => d === groupBy[i] || !groupBy.includes(d))
                                .map((d) => (
                                  <SelectItem key={d} value={d}>
                                    {t(dimensionNameKey(d), d)}
                                  </SelectItem>
                                ))}
                            </SelectContent>
                          </Select>
                        </div>
                      ))}
                  </Section>

                  {takesTime(draft, metric) && (
                    <Section title={t('dashboards.config.time', 'Time')}>
                      <div className="grid grid-cols-2 gap-3">
                        <div className="flex flex-col gap-1.5">
                          <Label htmlFor="widget-range">
                            {t('dashboards.config.range', 'Range')}
                          </Label>
                          <Select
                            value={draft.data.time.range || 'inherit'}
                            onValueChange={(range) =>
                              setDraft({
                                ...draft,
                                data: { ...draft.data, time: { ...draft.data.time, range } },
                              })
                            }
                          >
                            <SelectTrigger id="widget-range">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {(catalog.data?.time_ranges ?? ['inherit']).map((r) => (
                                <SelectItem key={r} value={r}>
                                  {t(`dashboards.range.${r}`, r)}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="flex flex-col gap-1.5">
                          <Label htmlFor="widget-compare">
                            {t('dashboards.config.compare', 'Compare')}
                          </Label>
                          <Select
                            value={draft.data.time.compare || 'none'}
                            onValueChange={(compare) =>
                              setDraft({
                                ...draft,
                                data: { ...draft.data, time: { ...draft.data.time, compare } },
                              })
                            }
                          >
                            <SelectTrigger id="widget-compare">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {(catalog.data?.comparisons ?? ['none']).map((c) => (
                                <SelectItem key={c} value={c}>
                                  {t(`dashboards.compare.${c}`, c)}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    </Section>
                  )}

                  {metric && (
                    <Section title={t('dashboards.config.visualization', 'Visualization')}>
                      <div
                        role="radiogroup"
                        aria-label={t('dashboards.config.visualization', 'Visualization')}
                        className="flex flex-wrap gap-1.5"
                      >
                        {vizzesFor(metric, groupBy.length).map((v, i) => {
                          const on = draft.viz.type === v
                          return (
                            <button
                              key={v}
                              type="button"
                              role="radio"
                              aria-checked={on}
                              onClick={() => setDraft(withViz(draft, metric, v))}
                              className={cn(
                                'rounded-md border px-2.5 py-1 text-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                                on ? 'border-primary bg-primary/10' : 'text-muted-foreground'
                              )}
                            >
                              {t(`dashboards.viz.${v}`, v)}
                              {i === 0 && (
                                <span className="ms-1 text-muted-foreground">
                                  {t('dashboards.config.auto', '(default)')}
                                </span>
                              )}
                            </button>
                          )
                        })}
                      </div>
                    </Section>
                  )}

                  {takesTarget(draft, metric) && (
                    <Section title={t('dashboards.config.target', 'Target')}>
                      <div className="grid grid-cols-[8rem_1fr_auto] items-end gap-2">
                        <div className="flex flex-col gap-1.5">
                          <Label htmlFor="widget-target-op">
                            {t('dashboards.config.targetOp', 'Better when')}
                          </Label>
                          <Select
                            value={draft.target?.op ?? NONE}
                            onValueChange={(op) => {
                              setTargetText(null)
                              setDraft(
                                op === NONE
                                  ? { ...draft, target: undefined }
                                  : {
                                      ...draft,
                                      target: {
                                        op: op as '<=' | '>=',
                                        value: draft.target?.value ?? 0,
                                      },
                                    }
                              )
                            }}
                          >
                            <SelectTrigger id="widget-target-op">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value={NONE}>
                                {t('dashboards.config.noTarget', 'No target')}
                              </SelectItem>
                              <SelectItem value="<=">
                                {t('dashboards.config.atMost', 'At most')}
                              </SelectItem>
                              <SelectItem value=">=">
                                {t('dashboards.config.atLeast', 'At least')}
                              </SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="flex flex-col gap-1.5">
                          <Label htmlFor="widget-target-value">
                            {t('dashboards.config.targetValue', 'Value')}
                          </Label>
                          <div className="flex items-center gap-2">
                            <Input
                              id="widget-target-value"
                              type="number"
                              min={0}
                              max={targetMax}
                              disabled={!draft.target}
                              aria-invalid={targetEmpty || undefined}
                              value={targetText ?? draft.target?.value ?? ''}
                              onChange={(e) => {
                                const raw = e.target.value
                                setTargetText(raw)
                                const n = Number(raw)
                                if (
                                  draft.target &&
                                  raw.trim() !== '' &&
                                  Number.isFinite(n) &&
                                  n >= 0 &&
                                  (targetMax === undefined || n <= targetMax)
                                )
                                  setDraft({ ...draft, target: { ...draft.target, value: n } })
                              }}
                            />
                            <span className="text-sm text-muted-foreground">
                              {t(`dashboards.config.unit.${unit}`, unit)}
                            </span>
                          </div>
                        </div>
                      </div>
                    </Section>
                  )}
                </>
              )}

              <Section title={t('dashboards.config.display', 'Display')}>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="widget-title">
                    {t('dashboards.config.widgetTitle', 'Title')}
                  </Label>
                  <Input
                    id="widget-title"
                    value={draft.title ?? ''}
                    maxLength={TITLE_MAX_LENGTH}
                    placeholder={
                      metric
                        ? t(metricNameKey(metric.id), metric.id)
                        : t('dashboards.widget.note', 'Note')
                    }
                    onChange={(e) => setDraft({ ...draft, title: e.target.value || undefined })}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t('dashboards.config.titleHint', 'Leave empty to use the translated name.')}
                  </p>
                </div>
              </Section>
            </div>
          </SheetBody>
        )}
        <SheetFooter>
          {draft && metric && !isNote && (
            <Button
              variant="ghost"
              className="me-auto"
              onClick={() => {
                setTargetText(null)
                setDraft({ ...newMetricSpec(metric, new Set()), id: draft.id })
              }}
            >
              {t('dashboards.config.reset', 'Reset to default')}
            </Button>
          )}
          <Button variant="outline" onClick={onCancel}>
            {t('dashboards.config.cancel', 'Cancel')}
          </Button>
          <Button onClick={() => draft && onApply(draft, freshPreview)} disabled={!canApply}>
            {t('dashboards.config.apply', 'Apply')}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}
