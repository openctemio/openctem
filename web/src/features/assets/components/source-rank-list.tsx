'use client'

/**
 * A ranked list of asset sources (RFC-069 §12) the person reorders by
 * dragging the handle, by keyboard on the handle (Space to pick up, arrow
 * keys to move, Space to drop, Escape to cancel, announced to screen
 * readers) or, on touch screens, with the up and down buttons. A person's
 * lock is pinned first and cannot move.
 */

import { useCallback, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import {
  DndContext,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core'
import { SortableContext, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import {
  ArrowDown,
  ArrowUp,
  FileUp,
  GripVertical,
  Lock,
  Plug,
  Radar,
  Rss,
  X,
  type LucideIcon,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { formatRelative } from '@/lib/format-date'
import { cn } from '@/lib/utils'
import {
  MAX_TTL_DAYS,
  lastSeenFor,
  moveItem,
  ruleParts,
  ttlValid,
  type RankableKind,
  type SourceRule,
  type SourceSummary,
} from '../lib/attribute-sources'

const KIND_ICON: Record<RankableKind, LucideIcon> = {
  integration: Plug,
  scan: Radar,
  import: FileUp,
  feed: Rss,
}

/** The label of a rule: its kind, or its source name with the kind. */
export function useRuleLabel() {
  const { t } = useTranslation()
  return useCallback(
    (source: string) => {
      const { kind, name } = ruleParts(source)
      const kindLabel = t(`assetSources.kind.${kind}`, kind)
      return name ? `${name} (${kindLabel})` : t(`assetSources.kindAll.${kind}`, kindLabel)
    },
    [t]
  )
}

interface RowProps {
  rule: SourceRule
  index: number
  total: number
  canEdit: boolean
  grabbed: boolean
  lastSeen: string | null
  scopeLabel: string
  onMove: (from: number, to: number) => void
  onChange: (rule: SourceRule) => void
  onRemove?: () => void
  onHandleKeyDown: (e: KeyboardEvent<HTMLButtonElement>, index: number) => void
  onHandleBlur: () => void
}

function SourceRow({
  rule,
  index,
  total,
  canEdit,
  grabbed,
  lastSeen,
  scopeLabel,
  onMove,
  onChange,
  onRemove,
  onHandleKeyDown,
  onHandleBlur,
}: RowProps) {
  const { t } = useTranslation()
  const label = useRuleLabel()(rule.source)
  const { kind } = ruleParts(rule.source)
  const Icon = KIND_ICON[kind] ?? Radar
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: rule.source, disabled: !canEdit })
  const ttlOk = ttlValid(rule.ttl_days)

  return (
    <li
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className={cn(
        'flex flex-wrap items-center gap-2 rounded-md border bg-background px-2 py-1.5 text-sm',
        (isDragging || grabbed) && 'ring-2 ring-primary',
        !rule.trusted && 'text-muted-foreground'
      )}
      data-testid={`source-row-${rule.source}`}
    >
      {canEdit && (
        <button
          type="button"
          ref={setActivatorNodeRef}
          {...attributes}
          {...listeners}
          aria-roledescription={t('assetSources.sortable', 'sortable')}
          aria-pressed={grabbed}
          aria-label={t('assetSources.dragHandle', 'Reorder {name}', { name: label })}
          onKeyDown={(e) => onHandleKeyDown(e, index)}
          onBlur={onHandleBlur}
          className="hidden cursor-grab touch-none rounded p-1 text-muted-foreground hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring sm:inline-flex pointer-coarse:hidden"
        >
          <GripVertical className="h-4 w-4" />
        </button>
      )}
      <Icon className="h-4 w-4 shrink-0" aria-hidden />
      <span className="min-w-0 flex-1 truncate font-medium">{label}</span>
      <span className="text-xs text-muted-foreground">
        {lastSeen
          ? t('assetSources.lastSeen', 'Last seen {when}', { when: formatRelative(lastSeen) })
          : t('assetSources.notSeen', 'Not seen yet')}
      </span>
      <label className="flex items-center gap-1 text-xs">
        <Input
          type="number"
          min={0}
          max={MAX_TTL_DAYS}
          className={cn('h-7 w-20', !ttlOk && 'border-destructive')}
          disabled={!canEdit}
          aria-invalid={!ttlOk}
          aria-label={t('assetSources.ttlFor', 'Days {name} counts', { name: label })}
          value={Number.isFinite(rule.ttl_days) ? rule.ttl_days : ''}
          onChange={(e) =>
            onChange({ ...rule, ttl_days: e.target.value === '' ? NaN : Number(e.target.value) })
          }
        />
        <span>{t('assetSources.days', 'days')}</span>
      </label>
      <Switch
        checked={rule.trusted}
        disabled={!canEdit}
        aria-label={t('assetSources.trustFor', '{name} may update {scope}', {
          name: label,
          scope: scopeLabel,
        })}
        onCheckedChange={(v) => onChange({ ...rule, trusted: v === true })}
      />
      {canEdit && (
        <span className="flex gap-0.5 sm:hidden pointer-coarse:flex">
          <Button
            type="button"
            size="icon"
            variant="ghost"
            className="h-7 w-7"
            disabled={index === 0}
            aria-label={t('assetSources.moveUp', 'Move {name} up', { name: label })}
            onClick={() => onMove(index, index - 1)}
          >
            <ArrowUp className="h-3.5 w-3.5" />
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            className="h-7 w-7"
            disabled={index === total - 1}
            aria-label={t('assetSources.moveDown', 'Move {name} down', { name: label })}
            onClick={() => onMove(index, index + 1)}
          >
            <ArrowDown className="h-3.5 w-3.5" />
          </Button>
        </span>
      )}
      {canEdit && onRemove && (
        <Button
          type="button"
          size="icon"
          variant="ghost"
          className="h-7 w-7"
          aria-label={t('assetSources.remove', 'Stop ranking {name} separately', { name: label })}
          onClick={onRemove}
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      )}
    </li>
  )
}

export interface SourceRankListProps {
  /** Accessible name of the list. */
  label: string
  /** What the trust switch allows ("Ownership and business context"). */
  scopeLabel: string
  rules: SourceRule[]
  sources: SourceSummary[]
  canEdit: boolean
  onChange: (rules: SourceRule[]) => void
}

export function SourceRankList({
  label,
  scopeLabel,
  rules,
  sources,
  canEdit,
  onChange,
}: SourceRankListProps) {
  const { t } = useTranslation()
  const ruleLabel = useRuleLabel()
  const [grabbed, setGrabbed] = useState<number | null>(null)
  const [announcement, setAnnouncement] = useState('')
  const original = useRef<SourceRule[] | null>(null)
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 4 } }))
  const ids = useMemo(() => rules.map((r) => r.source), [rules])
  const total = rules.length

  const move = useCallback(
    (from: number, to: number) => {
      const next = moveItem(rules, from, to)
      if (next === rules) return
      onChange(next)
      setAnnouncement(
        t('assetSources.announce.moved', '{name} moved to position {pos} of {total}', {
          name: ruleLabel(rules[from].source),
          pos: to + 1,
          total,
        })
      )
    },
    [rules, onChange, t, ruleLabel, total]
  )

  const onHandleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
      const name = ruleLabel(rules[index].source)
      if (e.key === ' ' || e.key === 'Enter') {
        e.preventDefault()
        if (grabbed === null) {
          original.current = rules
          setGrabbed(index)
          setAnnouncement(
            t(
              'assetSources.announce.picked',
              'Picked up {name}, position {pos} of {total}. Use the arrow keys to move, Space to drop, Escape to cancel.',
              { name, pos: index + 1, total }
            )
          )
        } else {
          setGrabbed(null)
          original.current = null
          setAnnouncement(
            t('assetSources.announce.dropped', '{name} dropped at position {pos} of {total}', {
              name,
              pos: index + 1,
              total,
            })
          )
        }
        return
      }
      if (grabbed === null) return
      if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        e.preventDefault()
        const to = e.key === 'ArrowUp' ? index - 1 : index + 1
        if (to < 0 || to >= total) return
        move(index, to)
        setGrabbed(to)
        return
      }
      if (e.key === 'Escape') {
        e.preventDefault()
        const before = original.current
        setGrabbed(null)
        original.current = null
        if (before) {
          onChange(before)
          const pos = before.findIndex((r) => r.source === rules[index].source) + 1
          setAnnouncement(
            t(
              'assetSources.announce.cancelled',
              'Move cancelled. {name} is back at position {pos}',
              {
                name,
                pos,
              }
            )
          )
        }
      }
    },
    [grabbed, rules, total, move, onChange, t, ruleLabel]
  )

  const onDragEnd = useCallback(
    (ev: DragEndEvent) => {
      if (!ev.over || ev.active.id === ev.over.id) return
      move(ids.indexOf(String(ev.active.id)), ids.indexOf(String(ev.over.id)))
    },
    [ids, move]
  )

  return (
    <div>
      <ol className="space-y-1.5" aria-label={label}>
        <li className="flex items-center gap-2 rounded-md border border-dashed px-2 py-1.5 text-sm text-muted-foreground">
          <Lock className="h-4 w-4" aria-hidden />
          <span className="flex-1">
            {t('assetSources.lockRow', 'A person’s lock on the asset page always wins')}
          </span>
        </li>
        <DndContext
          sensors={sensors}
          collisionDetection={closestCenter}
          onDragEnd={onDragEnd}
          accessibility={{
            screenReaderInstructions: {
              draggable: t(
                'assetSources.instructions',
                'Press Space to pick up a source, the arrow keys to move it, Space to drop it, Escape to cancel.'
              ),
            },
          }}
        >
          <SortableContext items={ids} strategy={verticalListSortingStrategy}>
            {rules.map((rule, i) => (
              <SourceRow
                key={rule.source}
                rule={rule}
                index={i}
                total={total}
                canEdit={canEdit}
                grabbed={grabbed === i}
                lastSeen={lastSeenFor(rule.source, sources)}
                scopeLabel={scopeLabel}
                onMove={move}
                onChange={(r) => onChange(rules.map((x, j) => (j === i ? r : x)))}
                onRemove={
                  ruleParts(rule.source).name
                    ? () => onChange(rules.filter((_, j) => j !== i))
                    : undefined
                }
                onHandleKeyDown={onHandleKeyDown}
                onHandleBlur={() => {
                  if (grabbed !== null) {
                    setGrabbed(null)
                    original.current = null
                  }
                }}
              />
            ))}
          </SortableContext>
        </DndContext>
      </ol>
      <div aria-live="assertive" role="status" className="sr-only">
        {announcement}
      </div>
    </div>
  )
}
