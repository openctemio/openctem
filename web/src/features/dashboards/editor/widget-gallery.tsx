'use client'

/**
 * "Add a widget": the catalog grouped by goal, searchable by name and
 * definition, each card with a live preview from the viewer's own data (the
 * preview endpoint computes in the caller's scope and is rate-limited per
 * person; at most PREVIEWS_PER_OPEN previews load per opening, lazily).
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import { Plus, Search, StickyNote } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { previewWidget, type WidgetValue } from '../api/widget-data'
import {
  useWidgetCatalog,
  vizzesFor,
  type CatalogMetric,
  type WidgetSpec,
} from '../api/widget-spec'
import { WidgetView } from '../components/widget-view'
import {
  METRIC_GROUPS,
  metricDefinitionKey,
  metricMeta,
  metricNameKey,
  type MetricGroup,
} from '../metrics'
import { newMetricSpec } from './spec-ops'

/** Live previews loaded per opening of the gallery (the server limits previews per person). */
export const PREVIEWS_PER_OPEN = 12

type Tab = 'all' | MetricGroup

export interface WidgetGalleryProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Spec ids already in the layout (a new id must not clash). */
  taken: ReadonlySet<string>
  /** Adds a metric widget (with its preview, when one loaded). */
  onAddMetric: (spec: WidgetSpec, metric: CatalogMetric, preview?: WidgetValue) => void
  onAddNote: () => void
}

/** Hands out at most `limit` preview slots for one opening. */
function useSlots(open: boolean, limit: number) {
  const used = useRef(0)
  useEffect(() => {
    if (open) used.current = 0
  }, [open])
  return () => {
    if (used.current >= limit) return false
    used.current += 1
    return true
  }
}

function PreviewCard({
  metric,
  taken,
  takeSlot,
  cache,
  onAdd,
}: {
  metric: CatalogMetric
  taken: ReadonlySet<string>
  takeSlot: () => boolean
  /** Previews already loaded in this opening (survives tab switches). */
  cache: Map<string, WidgetValue>
  onAdd: (spec: WidgetSpec, preview?: WidgetValue) => void
}) {
  const { t } = useTranslation()
  const spec = useMemo(() => newMetricSpec(metric, taken), [metric, taken])
  const ref = useRef<HTMLDivElement>(null)
  const cached = cache.get(metric.id)
  const [preview, setPreview] = useState<WidgetValue | undefined>(cached)
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'skipped'>(
    cached ? 'done' : 'idle'
  )

  useEffect(() => {
    const el = ref.current
    if (!el || state !== 'idle') return
    const load = () => {
      if (!takeSlot()) {
        setState('skipped')
        return
      }
      setState('loading')
      previewWidget('metric', spec as unknown as Record<string, unknown>)
        .then((v) => {
          if (v) cache.set(metric.id, v)
          setPreview(v)
        })
        .catch(() => setPreview(undefined))
        .finally(() => setState('done'))
    }
    if (typeof IntersectionObserver === 'undefined') {
      load()
      return
    }
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        io.disconnect()
        load()
      }
    })
    io.observe(el)
    return () => io.disconnect()
  }, [spec, state, takeSlot, cache, metric.id])

  const name = t(metricNameKey(metric.id), metric.id)
  return (
    <div
      ref={ref}
      className="flex min-w-0 flex-col gap-2 rounded-lg border p-3"
      data-testid={`gallery-card-${metric.id}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium">{name}</p>
          <p className="line-clamp-2 text-xs text-muted-foreground">
            {t(metricDefinitionKey(metric.id), '')}
          </p>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="shrink-0"
          onClick={() => onAdd(spec, preview)}
          aria-label={t('dashboards.gallery.addNamed', 'Add {name}', { name })}
        >
          <Plus className="me-1 h-3.5 w-3.5" aria-hidden />
          {t('dashboards.gallery.add', 'Add')}
        </Button>
      </div>
      <div className="pointer-events-none min-h-[7rem] min-w-0" aria-hidden={state !== 'done'}>
        {state === 'loading' ? (
          <Skeleton className="h-28 w-full" />
        ) : state === 'done' && preview ? (
          <WidgetView
            widget={{ widget_type: 'metric', config: spec as unknown as Record<string, unknown> }}
            value={preview}
            bare
          />
        ) : state === 'done' ? (
          <p className="text-xs text-muted-foreground">
            {t('dashboards.gallery.previewFailed', 'No preview right now. You can still add it.')}
          </p>
        ) : state === 'skipped' ? (
          <p className="text-xs text-muted-foreground">
            {t('dashboards.gallery.previewLater', 'Add it to see your figures.')}
          </p>
        ) : (
          <Skeleton className="h-28 w-full" />
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        {vizzesFor(metric, 0)
          .map((v) => t(`dashboards.viz.${v}`, v))
          .join(' · ')}
      </p>
    </div>
  )
}

export function WidgetGallery({
  open,
  onOpenChange,
  taken,
  onAddMetric,
  onAddNote,
}: WidgetGalleryProps) {
  const { t } = useTranslation()
  const catalog = useWidgetCatalog()
  const [tab, setTab] = useState<Tab>('all')
  const [query, setQuery] = useState('')
  const takeSlot = useSlots(open, PREVIEWS_PER_OPEN)
  const [cache] = useState(() => new Map<string, WidgetValue>())
  useEffect(() => {
    if (!open) cache.clear()
  }, [open, cache])

  const q = query.trim().toLowerCase()
  const metrics = useMemo(() => {
    const all = catalog.data?.metrics ?? []
    return all.filter((m) => {
      const group = metricMeta(m.id)?.group ?? (m.group as MetricGroup)
      if (tab !== 'all' && group !== tab) return false
      if (!q) return true
      const hay =
        `${t(metricNameKey(m.id), m.id)} ${t(metricDefinitionKey(m.id), '')}`.toLowerCase()
      return hay.includes(q)
    })
  }, [catalog.data, tab, q, t])

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        data-testid="widget-gallery-sheet"
        className="w-full max-w-none min-w-0 sm:max-w-[min(34rem,100vw)]"
      >
        <SheetHeader>
          <SheetTitle>{t('dashboards.gallery.title', 'Add a widget')}</SheetTitle>
          <SheetDescription>
            {t(
              'dashboards.gallery.description',
              'Previews show your own figures. Add a widget, then change what it counts and how it is drawn.'
            )}
          </SheetDescription>
        </SheetHeader>
        <SheetBody>
          <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)} className="min-w-0 gap-3">
            <div className="relative min-w-0">
              <Search
                className="absolute start-2.5 top-2.5 h-4 w-4 text-muted-foreground"
                aria-hidden
              />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('dashboards.gallery.search', 'Search widgets')}
                aria-label={t('dashboards.gallery.search', 'Search widgets')}
                className="ps-8"
              />
            </div>
            <TabsList aria-label={t('dashboards.gallery.groups', 'Widget groups')}>
              {(['all', ...METRIC_GROUPS] as Tab[]).map((g) => (
                <TabsTrigger key={g} value={g}>
                  {g === 'all' ? t('dashboards.gallery.all', 'All') : t(`dashboards.group.${g}`, g)}
                </TabsTrigger>
              ))}
            </TabsList>
            {tab === 'all' && !q && (
              <button
                type="button"
                onClick={onAddNote}
                className="flex items-center gap-3 rounded-lg border border-dashed p-3 text-start hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                <StickyNote className="h-5 w-5 text-muted-foreground" aria-hidden />
                <span>
                  <span className="block text-sm font-medium">
                    {t('dashboards.widget.note', 'Note')}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {t('dashboards.gallery.noteHint', 'Text for context, links or instructions.')}
                  </span>
                </span>
              </button>
            )}
            <TabsContent value={tab} className="flex min-w-0 flex-col gap-3">
              {catalog.isLoading ? (
                <Skeleton className="h-40 w-full" />
              ) : catalog.error ? (
                <p className="text-sm text-destructive" role="alert">
                  {t('dashboards.gallery.failed', 'The widget list could not be loaded.')}
                </p>
              ) : metrics.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('dashboards.gallery.none', 'No widget matches.')}
                </p>
              ) : (
                <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-3">
                  {metrics.map((m) => (
                    <PreviewCard
                      key={m.id}
                      metric={m}
                      taken={taken}
                      takeSlot={takeSlot}
                      cache={cache}
                      onAdd={(spec, preview) => onAddMetric(spec, m, preview)}
                    />
                  ))}
                </div>
              )}
            </TabsContent>
          </Tabs>
        </SheetBody>
      </SheetContent>
    </Sheet>
  )
}
