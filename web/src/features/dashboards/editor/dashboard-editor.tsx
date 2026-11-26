'use client'

/**
 * Customize a dashboard in place: add widgets from the gallery, configure
 * each in the side panel, move and resize them by pointer or keyboard, undo
 * and redo, then Save (or Cancel to drop every change). Each widget shows its
 * stored figures, or its preview when it is new or changed.
 *
 * Keyboard, with a widget focused: arrows move it, Shift+Left/Right change its
 * width, Shift+Up/Down the rows it spans beside its neighbours (a widget is
 * as tall as its content; its rows only place it),
 * Enter configures, D duplicates, Delete removes (with Undo). Ctrl/Cmd+Z and
 * Ctrl/Cmd+Shift+Z undo and redo. Every change is announced.
 */

import { useCallback, useEffect, useReducer, useRef, useState } from 'react'
import {
  DndContext,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core'
import { SortableContext, rectSortingStrategy, useSortable } from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import {
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  ArrowUpToLine,
  Copy,
  GripVertical,
  Minus,
  MoreHorizontal,
  Plus,
  Redo2,
  Save,
  Settings2,
  Trash2,
  Undo2,
  X,
} from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { ActionMenu } from '@/components/ui/action-menu'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import type { Dashboard, DashboardKind, DashboardWidget } from '../api/dashboards.types'
import { updateDashboard, updateOrgDashboard } from '../api/use-dashboards-api'
import type { DashboardData, WidgetValue } from '../api/widget-data'
import type { CatalogMetric, WidgetSpec } from '../api/widget-spec'
import { specOf } from '../api/widget-adapter'
import { rowsOnView } from '../components/dashboard-view'
import { WidgetView } from '../components/widget-view'
import {
  colSpanFor,
  editorColumnsClass,
  editorSpanClass,
  gridColumnSpan,
  normalizeColumns,
  widgetRowSpan,
} from '../layout'
import { defaultWidgetTitle, metricNameKey } from '../metrics'
import { initHistory, push, redo, undo, type History } from './history'
import * as ops from './layout-ops'
import { newNoteSpec, specShape, widgetFromSpec } from './spec-ops'
import { WidgetConfigPanel } from './widget-config-panel'
import { WidgetGallery } from './widget-gallery'

/** A layout entry with an editor-only key (never saved). */
type EditorWidget = DashboardWidget & { uid: string }

let seq = 0
const nextUid = () => `e${(seq++).toString(36)}`

type Action = { type: 'set'; layout: EditorWidget[] } | { type: 'undo' } | { type: 'redo' }

function reducer(h: History<EditorWidget[]>, a: Action): History<EditorWidget[]> {
  switch (a.type) {
    case 'set':
      return push(h, a.layout)
    case 'undo':
      return undo(h)
    case 'redo':
      return redo(h)
  }
}

/**
 * Keeps editor keys through a layout operation (which copies entries); a
 * copy that repeats a key (duplicate) or an entry without one gets a new key.
 */
function withUids(next: DashboardWidget[]): EditorWidget[] {
  const seen = new Set<string>()
  return next.map((w) => {
    const uid = (w as EditorWidget).uid
    if (uid && !seen.has(uid)) {
      seen.add(uid)
      return w as EditorWidget
    }
    const fresh = nextUid()
    seen.add(fresh)
    return { ...w, uid: fresh }
  })
}

function strip(layout: EditorWidget[]): DashboardWidget[] {
  return layout.map(({ uid: _uid, ...w }, i) => ({ ...w, x: 0, y: i }))
}

export interface DashboardEditorProps {
  dashboard: Dashboard
  kind: DashboardKind
  data?: DashboardData
  onExit: (saved: boolean) => void
}

export function DashboardEditor({ dashboard, kind, data, onExit }: DashboardEditorProps) {
  const { t } = useTranslation()
  const cols = normalizeColumns(dashboard.columns)

  // Each stored widget keeps its stored figures through moves. Computed once
  // per editing session: a lazy state initializer runs only on first render.
  const [initial] = useState(() => {
    const values = new Map<string, WidgetValue>()
    const layout = (dashboard.layout ?? []).map((w, i) => {
      const uid = nextUid()
      const v = data?.widgets.find((x) => x.index === i)
      if (v) values.set(uid, v)
      return { ...w, uid }
    })
    return { layout, values }
  })

  const [history, dispatch] = useReducer(reducer, initial.layout, initHistory)
  const layout = history.present
  const [values, setValues] = useState(initial.values)
  const [galleryOpen, setGalleryOpen] = useState(false)
  const [editing, setEditing] = useState<{ uid: string; spec: WidgetSpec } | null>(null)
  const [saving, setSaving] = useState(false)
  const [announcement, setAnnouncement] = useState('')
  const [focusUid, setFocusUid] = useState<string | null>(null)
  const cardRefs = useRef(new Map<string, HTMLDivElement>())

  const dirty = history.past.length > 0
  const historyRef = useRef(history)
  useEffect(() => {
    historyRef.current = history
  }, [history])
  const [confirmDiscard, setConfirmDiscard] = useState(false)

  // Leaving the page with unsaved changes asks the browser to confirm.
  useEffect(() => {
    if (!dirty) return
    const guard = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', guard)
    return () => window.removeEventListener('beforeunload', guard)
  }, [dirty])
  const set = useCallback((next: DashboardWidget[], message?: string) => {
    dispatch({ type: 'set', layout: withUids(next) })
    if (message) setAnnouncement(message)
  }, [])

  const nameOf = useCallback(
    (w: DashboardWidget) => {
      const spec = specOf(w)
      if (spec?.title) return spec.title
      if (spec?.data.kind === 'note') return t('dashboards.widget.note', 'Note')
      if (spec?.data.metric)
        return defaultWidgetTitle(spec, t) ?? t(metricNameKey(spec.data.metric), spec.data.metric)
      return t('dashboards.widget.legacy', 'Earlier tile')
    },
    [t]
  )

  // Focus follows the widget a keyboard action moved.
  useEffect(() => {
    if (focusUid) cardRefs.current.get(focusUid)?.focus()
  }, [focusUid, layout])

  // A widget just added is shown and focused when its settings panel
  // closes, instead of focus going back to "Add widget": a new widget lands
  // at the end of a long dashboard, out of sight otherwise.
  const reveal = useRef<string | null>(null)
  const revealAdded = () => {
    const uid = reveal.current
    reveal.current = null
    const el = uid ? cardRefs.current.get(uid) : undefined
    if (!el) return false
    el.scrollIntoView?.({ block: 'center' })
    el.focus({ preventScroll: true })
    return true
  }

  const removeAt = (i: number) => {
    const w = layout[i]
    set(
      ops.remove(layout, i),
      t('dashboards.editor.removed', '{name} removed', { name: nameOf(w) })
    )
    // The removal is the newest history step. If anything changed after it, a
    // plain undo would revert that change instead, so the widget is put back
    // at its index.
    const stepsAfterRemoval = historyRef.current.past.length + 1
    toast(t('dashboards.editor.removed', '{name} removed', { name: nameOf(w) }), {
      action: {
        label: t('dashboards.editor.undo', 'Undo'),
        onClick: () => {
          const h = historyRef.current
          if (h.past.length === stepsAfterRemoval) dispatch({ type: 'undo' })
          else set(ops.insert(h.present, w, i))
        },
      },
    })
  }

  const onKey = (e: React.KeyboardEvent, i: number) => {
    const w = layout[i]
    const name = nameOf(w)
    let next: DashboardWidget[] | null = null
    let msg = ''
    if (e.shiftKey && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
      next = ops.resizeWidth(layout, i, e.key === 'ArrowRight' ? 1 : -1, cols)
      const span = colSpanFor((next[i] ?? w).w, cols)
      msg = t('dashboards.editor.width', '{name}: {span} of {cols} columns wide', {
        name,
        span,
        cols,
      })
    } else if (e.shiftKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
      next = ops.resizeHeight(layout, i, e.key === 'ArrowDown' ? 1 : -1)
      msg = t('dashboards.editor.rows', '{name}: spans {rows} rows beside its neighbours', {
        name,
        rows: (next[i] ?? w).h,
      })
    } else if (!e.shiftKey && (e.key === 'ArrowLeft' || e.key === 'ArrowUp')) {
      next = ops.move(layout, i, i - 1)
      msg = t('dashboards.editor.position', '{name}: position {pos} of {total}', {
        name,
        pos: Math.max(1, i),
        total: layout.length,
      })
    } else if (!e.shiftKey && (e.key === 'ArrowRight' || e.key === 'ArrowDown')) {
      next = ops.move(layout, i, i + 1)
      msg = t('dashboards.editor.position', '{name}: position {pos} of {total}', {
        name,
        pos: Math.min(layout.length, i + 2),
        total: layout.length,
      })
    } else if (e.key === 'Enter') {
      const spec = specOf(w)
      if (spec) {
        e.preventDefault()
        setEditing({ uid: (w as EditorWidget).uid, spec })
      }
      return
    } else if (e.key === 'd' || e.key === 'D') {
      next = ops.duplicate(layout, i)
      msg = t('dashboards.editor.duplicated', '{name} duplicated', { name })
    } else if (e.key === 'Delete' || e.key === 'Backspace') {
      e.preventDefault()
      removeAt(i)
      return
    }
    if (next) {
      e.preventDefault()
      setFocusUid((w as EditorWidget).uid)
      set(next, msg)
    }
  }

  // Undo / redo from anywhere in the editor.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== 'z') return
      const target = e.target instanceof Element ? e.target : null
      if (target?.closest('input, textarea, [contenteditable=true], [role=dialog]')) return
      e.preventDefault()
      dispatch({ type: e.shiftKey ? 'redo' : 'undo' })
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 6 } }))
  const onDragEnd = (e: DragEndEvent) => {
    if (!e.over || e.active.id === e.over.id) return
    const from = layout.findIndex((w) => w.uid === e.active.id)
    const to = layout.findIndex((w) => w.uid === e.over!.id)
    if (from >= 0 && to >= 0) set(ops.move(layout, from, to))
  }

  const addMetric = (spec: WidgetSpec, metric: CatalogMetric, preview?: WidgetValue) => {
    const w = { ...widgetFromSpec(spec, specShape(spec, metric)), uid: nextUid() }
    if (preview) setValues((m) => new Map(m).set(w.uid, preview))
    set(ops.insert(layout, w), t('dashboards.editor.added', '{name} added', { name: nameOf(w) }))
    setGalleryOpen(false)
    setEditing({ uid: w.uid, spec })
    reveal.current = w.uid
  }

  const addNote = () => {
    setGalleryOpen(false)
    const spec = newNoteSpec('', ops.takenIds(layout))
    setEditing({ uid: '', spec })
  }

  const applyConfig = (spec: WidgetSpec, preview?: WidgetValue) => {
    if (!editing) return
    const i = layout.findIndex((w) => w.uid === editing.uid)
    if (i < 0) {
      // A new note: added on Apply.
      const w = { ...widgetFromSpec(spec, undefined), uid: nextUid() }
      set(ops.insert(layout, w), t('dashboards.editor.added', '{name} added', { name: nameOf(w) }))
      reveal.current = w.uid
    } else {
      const prev = layout[i]
      const changedData =
        JSON.stringify(specOf(prev)?.data) !== JSON.stringify(spec.data) ||
        specOf(prev)?.viz.type !== spec.viz.type
      set(
        ops.replaceAt(layout, i, {
          ...prev,
          widget_type: spec.data.kind,
          config: spec as unknown as Record<string, unknown>,
        })
      )
      if (preview) setValues((m) => new Map(m).set(prev.uid, preview))
      else if (changedData)
        setValues((m) => {
          const n = new Map(m)
          n.delete(prev.uid)
          return n
        })
    }
    setEditing(null)
  }

  const save = async () => {
    setSaving(true)
    try {
      const input = {
        name: dashboard.name,
        description: dashboard.description,
        columns: dashboard.columns,
        layout: strip(layout),
      }
      if (kind === 'organization') await updateOrgDashboard(dashboard.id, input)
      else await updateDashboard(dashboard.id, input)
      toast.success(t('dashboards.editor.saved', 'Dashboard saved'))
      onExit(true)
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div
        // Sticks below the app header (h-12, sticky top-0), never under it.
        className="sticky top-12 z-10 flex flex-wrap items-center gap-2 rounded-lg border bg-background/95 p-2 backdrop-blur"
        role="toolbar"
        aria-label={t('dashboards.editor.toolbar', 'Dashboard editor')}
      >
        <p className="me-auto text-sm font-medium">
          {t('dashboards.editor.title', 'Customizing "{name}"', { name: dashboard.name })}
        </p>
        <Button
          variant="ghost"
          size="icon"

          onClick={() => dispatch({ type: 'undo' })}
          disabled={history.past.length === 0}
          aria-label={t('dashboards.editor.undo', 'Undo')}
        >
          <Undo2 className="h-4 w-4" aria-hidden />
        </Button>
        <Button
          variant="ghost"
          size="icon"

          onClick={() => dispatch({ type: 'redo' })}
          disabled={history.future.length === 0}
          aria-label={t('dashboards.editor.redo', 'Redo')}
        >
          <Redo2 className="h-4 w-4" aria-hidden />
        </Button>
        <Button variant="outline" size="sm" onClick={() => setGalleryOpen(true)}>
          <Plus className="me-1.5 h-4 w-4" aria-hidden />
          {t('dashboards.editor.add', 'Add widget')}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => (dirty ? setConfirmDiscard(true) : onExit(false))}
          disabled={saving}
        >
          <X className="me-1.5 h-4 w-4" aria-hidden />
          {t('dashboards.config.cancel', 'Cancel')}
        </Button>
        <Button size="sm" onClick={save} disabled={saving || !dirty}>
          <Save className="me-1.5 h-4 w-4" aria-hidden />
          {t('dashboards.editor.save', 'Save')}
        </Button>
      </div>
      {/* Keys mean nothing on a touch screen: a phone gets the touch wording
          (the keyboard wording stays the cards' description for assistive
          technology). */}
      <p className="text-xs text-muted-foreground sm:hidden">
        {t(
          'dashboards.editor.helpTouch',
          'Drag a widget by its handle to move it, or use its menu to move, resize, duplicate or remove it.'
        )}
      </p>
      <p id="dashboard-editor-help" className="text-xs text-muted-foreground max-sm:sr-only">
        {t(
          'dashboards.editor.help',
          'Drag a widget by its handle, or focus it and use the arrow keys to move it, Shift and the left or right arrow to change its width, Shift and the up or down arrow to change how many rows it spans beside its neighbours, Enter to configure, D to duplicate and Delete to remove.'
        )}
      </p>
      <div aria-live="polite" className="sr-only" data-testid="editor-announcer">
        {announcement}
      </div>

      {layout.length === 0 ? (
        <button
          type="button"
          onClick={() => setGalleryOpen(true)}
          className="rounded-lg border border-dashed py-12 text-center text-sm text-muted-foreground hover:bg-muted/40"
        >
          {t('dashboards.editor.empty', 'No widgets yet. Add your first widget.')}
        </button>
      ) : (
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
          <SortableContext items={layout.map((w) => w.uid)} strategy={rectSortingStrategy}>
            {/* Rows are as tall as their content, as on the dashboard
                (DashboardView): a preview stands as tall as the widget will.
                A widget's rows only place it beside its neighbours. */}
            <div
              className={cn('grid gap-3 sm:gap-4', editorColumnsClass(cols))}
              data-testid="editor-grid"
            >
              {layout.map((w, i) => (
                <EditorCard
                  key={w.uid}
                  widget={w}
                  index={i}
                  total={layout.length}
                  columns={cols}
                  name={nameOf(w)}
                  value={values.get(w.uid)}
                  asOf={data?.computed_at}
                  cardRef={(el) => {
                    if (el) cardRefs.current.set(w.uid, el)
                    else cardRefs.current.delete(w.uid)
                  }}
                  onKeyDown={(e) => onKey(e, i)}
                  onMove={(d) => set(ops.move(layout, i, i + d))}
                  onWidth={(d) => set(ops.resizeWidth(layout, i, d, cols))}
                  onHeight={(d) => set(ops.resizeHeight(layout, i, d))}
                  onConfigure={() => {
                    const spec = specOf(w)
                    if (spec) setEditing({ uid: w.uid, spec })
                  }}
                  onDuplicate={() => set(ops.duplicate(layout, i))}
                  onRemove={() => removeAt(i)}
                />
              ))}
            </div>
          </SortableContext>
        </DndContext>
      )}

      <WidgetGallery
        open={galleryOpen}
        onOpenChange={setGalleryOpen}
        taken={ops.takenIds(layout)}
        onAddMetric={addMetric}
        onAddNote={addNote}
      />
      <ConfirmDialog
        open={confirmDiscard}
        onOpenChange={setConfirmDiscard}
        destructive
        title={t('dashboards.editor.discardTitle', 'Discard your changes?')}
        desc={t(
          'dashboards.editor.discardDesc',
          'The changes you made to this dashboard are lost if you leave without saving.'
        )}
        confirmText={t('dashboards.editor.discard', 'Discard changes')}
        cancelBtnText={t('dashboards.editor.keepEditing', 'Keep editing')}
        handleConfirm={() => {
          setConfirmDiscard(false)
          onExit(false)
        }}
      />
      <WidgetConfigPanel
        spec={editing?.spec ?? null}
        initialValue={editing ? values.get(editing.uid) : undefined}
        onCancel={() => setEditing(null)}
        onApply={applyConfig}
        onCloseFocus={revealAdded}
      />
    </div>
  )
}

function EditorCard({
  widget,
  index,
  total,
  columns,
  name,
  value,
  asOf,
  cardRef,
  onKeyDown,
  onMove,
  onWidth,
  onHeight,
  onConfigure,
  onDuplicate,
  onRemove,
}: {
  widget: EditorWidget
  index: number
  total: number
  columns: number
  name: string
  value?: WidgetValue
  asOf?: string
  cardRef: (el: HTMLDivElement | null) => void
  onKeyDown: (e: React.KeyboardEvent) => void
  onMove: (delta: number) => void
  onWidth: (delta: number) => void
  onHeight: (delta: number) => void
  onConfigure: () => void
  onDuplicate: () => void
  onRemove: () => void
}) {
  const { t } = useTranslation()
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: widget.uid })
  const typed = !!specOf(widget)
  const span = colSpanFor(widget.w, columns)
  // Kit icon buttons at the kit's sizes: every control of the header row
  // shares one height (36 px on a phone, 32 px from 640 px).
  const iconBtn = 'shrink-0'
  return (
    <div
      ref={setNodeRef}
      style={
        {
          '--span': gridColumnSpan(span),
          '--span-sm': gridColumnSpan(Math.min(2, span)),
          gridRow: widgetRowSpan(rowsOnView(widget, value, columns)),
          transform: CSS.Transform.toString(transform),
          transition,
        } as React.CSSProperties
      }
      className={cn(
        // On a phone the editor is a list: one row per widget, no preview.
        'flex min-w-0 flex-col max-sm:[grid-row:auto]',
        editorSpanClass(columns),
        isDragging && 'z-20 opacity-80'
      )}
    >
      <div
        ref={cardRef}
        tabIndex={0}
        role="group"
        aria-roledescription={t('dashboards.editor.widgetRole', 'widget')}
        aria-label={t('dashboards.editor.cardLabel', '{name}, position {pos} of {total}', {
          name,
          pos: index + 1,
          total,
        })}
        aria-describedby="dashboard-editor-help"
        onKeyDown={(e) => {
          if (e.target === e.currentTarget) onKeyDown(e)
        }}
        className="flex min-w-0 flex-1 flex-col rounded-lg ring-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
        data-testid="editor-card"
      >
        {/* The chrome never outgrows its widget: handle, title (truncated,
            full name on hover), Configure and More; Duplicate and Remove show
            inline only when the widget itself is wide enough (container query). */}
        <div
          className="@container flex min-w-0 items-center gap-0.5 overflow-hidden rounded-t-lg border bg-muted/40 px-1 py-0.5 max-sm:rounded-b-lg sm:border-b-0"
          data-testid="editor-chrome"
        >
          <Button
            type="button"
            variant="ghost"
            size="icon"
            ref={setActivatorNodeRef}
            {...attributes}
            {...listeners}
            tabIndex={-1}
            className={cn(iconBtn, 'cursor-grab touch-none text-muted-foreground')}
            aria-label={t('dashboards.editor.drag', 'Drag {name}', { name })}
          >
            <GripVertical className="h-4 w-4" aria-hidden />
          </Button>
          <span
            className="min-w-0 flex-1 truncate px-1 text-sm text-muted-foreground sm:text-xs"
            title={name}
            data-cut-tooltip
          >
            {name}
          </span>
          {typed && (
            <Button
              variant="ghost"
              size="icon"
              className={iconBtn}
              tabIndex={-1}
              onClick={onConfigure}
              aria-label={t('dashboards.editor.configure', 'Configure {name}', { name })}
            >
              <Settings2 className="h-3.5 w-3.5" aria-hidden />
            </Button>
          )}
          <Button
            variant="ghost"
            size="icon"
            className={cn(iconBtn, 'hidden @[22rem]:inline-flex')}
            tabIndex={-1}
            onClick={onDuplicate}
            aria-label={t('dashboards.editor.duplicate', 'Duplicate {name}', { name })}
          >
            <Copy className="h-3.5 w-3.5" aria-hidden />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className={cn(iconBtn, 'hidden text-destructive @[22rem]:inline-flex')}
            tabIndex={-1}
            onClick={onRemove}
            aria-label={t('dashboards.editor.remove', 'Remove {name}', { name })}
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
          </Button>
          <ActionMenu
            title={name}
            label={t('dashboards.editor.more', 'More actions for {name}', { name })}
            items={[
              {
                id: 'earlier',
                label: t('dashboards.editor.moveEarlier', 'Move earlier'),
                icon: ArrowLeft,
                shortcut: '←',
                section: 'move',
                disabledReason:
                  index === 0 ? t('dashboards.editor.reason.first', 'Already first') : undefined,
                onSelect: () => onMove(-1),
              },
              {
                id: 'later',
                label: t('dashboards.editor.moveLater', 'Move later'),
                icon: ArrowRight,
                shortcut: '→',
                section: 'move',
                disabledReason:
                  index === total - 1
                    ? t('dashboards.editor.reason.last', 'Already last')
                    : undefined,
                onSelect: () => onMove(1),
              },
              {
                id: 'narrower',
                label: t('dashboards.editor.narrower', 'Narrower'),
                icon: Minus,
                shortcut: '⇧←',
                section: 'size',
                disabledReason:
                  span <= 1
                    ? t('dashboards.editor.reason.narrowest', 'Already as narrow as it goes')
                    : undefined,
                onSelect: () => onWidth(-1),
              },
              {
                id: 'wider',
                label: t('dashboards.editor.wider', 'Wider'),
                icon: Plus,
                shortcut: '⇧→',
                section: 'size',
                disabledReason:
                  span >= columns
                    ? t('dashboards.editor.reason.widest', 'Already as wide as it goes')
                    : undefined,
                onSelect: () => onWidth(1),
              },
              {
                id: 'fewer-rows',
                label: t('dashboards.editor.fewerRows', 'Span one row fewer'),
                icon: ArrowUpToLine,
                shortcut: '⇧↑',
                section: 'size',
                disabledReason:
                  widget.h <= ops.MIN_ROWS
                    ? t('dashboards.editor.reason.oneRow', 'Already spans one row')
                    : undefined,
                onSelect: () => onHeight(-1),
              },
              {
                id: 'more-rows',
                label: t('dashboards.editor.moreRows', 'Span one more row'),
                icon: ArrowDownToLine,
                shortcut: '⇧↓',
                section: 'size',
                disabledReason:
                  widget.h >= ops.MAX_ROWS
                    ? t('dashboards.editor.reason.mostRows', 'Already spans the most rows')
                    : undefined,
                onSelect: () => onHeight(1),
              },
              {
                id: 'duplicate',
                label: t('dashboards.editor.duplicateShort', 'Duplicate'),
                icon: Copy,
                shortcut: 'D',
                section: 'duplicate',
                onSelect: onDuplicate,
              },
              {
                id: 'remove',
                label: t('dashboards.editor.removeShort', 'Remove'),
                icon: Trash2,
                shortcut: t('dashboards.editor.keyDelete', 'Del'),
                destructive: true,
                onSelect: onRemove,
              },
            ]}
            trigger={
              <Button
                variant="ghost"
                size="icon"
                className={iconBtn}
                tabIndex={-1}
                aria-label={t('dashboards.editor.more', 'More actions for {name}', { name })}
              >
                <MoreHorizontal className="h-4 w-4" aria-hidden />
              </Button>
            }
          />
        </div>
        <div className="pointer-events-none flex min-w-0 flex-1 flex-col max-sm:hidden">
          <WidgetView
            widget={widget}
            menu={false}
            value={
              value ??
              (typed
                ? {
                    id: '',
                    index,
                    widget_type: widget.widget_type,
                    state: 'building',
                    reason: 'pending',
                  }
                : undefined)
            }
            asOf={asOf}
            // As on the dashboard: the freshness line shows only when a
            // widget's time differs from the page's.
            pageAsOf={asOf}
            className="flex-1 rounded-t-none"
          />
        </div>
      </div>
    </div>
  )
}
