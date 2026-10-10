'use client'

/**
 * The organization's approval rules in order (RFC-073 §4.1): each with its
 * condition chips and what it needs; drag a rule (or use the arrow buttons,
 * or the keyboard on the handle) to change the order. Order matters: on a
 * tie in approvals the first matching rule decides who approves.
 */

import type { KeyboardEvent } from 'react'
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core'
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { ArrowDown, ArrowUp, GripVertical, Pencil, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { activeConditions, conditionLabel } from '@/features/scans/lib/approval-rules'
import type { ScanApprovalMode, ScanApprovalRule } from '@/lib/api/scan-approval-hooks'
import { cn } from '@/lib/utils'
import { approversText } from './approval-requirement'

export interface ApprovalRuleListProps {
  rules: ScanApprovalRule[]
  mode: ScanApprovalMode
  canEdit: boolean
  onMove: (from: number, to: number) => void
  onEdit: (index: number) => void
  onChange: (index: number, patch: Partial<ScanApprovalRule>) => void
  onRemove: (index: number) => void
}

interface RowProps extends Omit<ApprovalRuleListProps, 'rules' | 'onMove'> {
  rule: ScanApprovalRule
  index: number
  total: number
  onMove: (from: number, to: number) => void
}

function RuleRow({
  rule,
  index,
  total,
  mode,
  canEdit,
  onMove,
  onEdit,
  onChange,
  onRemove,
}: RowProps) {
  const { t } = useTranslation()
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: rule.id || `new-${index}`, disabled: !canEdit })
  const chips = activeConditions(rule.conditions)
  const onHandleKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowUp' && e.altKey && index > 0) {
      e.preventDefault()
      onMove(index, index - 1)
    }
    if (e.key === 'ArrowDown' && e.altKey && index < total - 1) {
      e.preventDefault()
      onMove(index, index + 1)
    }
  }
  return (
    <li
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className={cn(
        'flex flex-wrap items-start gap-3 bg-background p-3',
        isDragging && 'ring-2 ring-primary'
      )}
      data-testid={`approval-rule-${index}`}
    >
      {canEdit && (
        <button
          type="button"
          ref={setActivatorNodeRef}
          {...attributes}
          {...listeners}
          onKeyDown={(e) => {
            onHandleKey(e)
            listeners?.onKeyDown?.(e)
          }}
          aria-label={t('scans.ruleList.reorder', 'Reorder {name}', { name: rule.name })}
          className="mt-0.5 cursor-grab touch-none rounded p-1 text-muted-foreground hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <GripVertical className="size-4" />
        </button>
      )}
      <div className="min-w-0 flex-1 space-y-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">{index + 1}.</span>
          <span className="font-medium">{rule.name}</span>
          {rule.monitor && (
            <Badge variant="outline">{t('scans.approvalSettings.monitor', 'Monitor')}</Badge>
          )}
          {!rule.enabled && (
            <Badge variant="secondary">{t('scans.approvalSettings.disabled', 'Off')}</Badge>
          )}
        </div>
        <div className="flex flex-wrap gap-1">
          {chips.length === 0 ? (
            <Badge variant="outline">{t('scans.ruleEditor.everyScan', 'Every scan')}</Badge>
          ) : (
            chips.map((k) => (
              <Badge key={k} variant="secondary" className="font-normal">
                {conditionLabel(t, rule.conditions, k)}
              </Badge>
            ))
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          {approversText(t, {
            mode,
            required: true,
            approvals: rule.requirement.approvals,
            approver_roles: rule.requirement.approver_roles,
            approver_user_ids: rule.requirement.approver_user_ids,
          })}
        </p>
      </div>
      {canEdit && (
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 text-sm">
            <Switch
              checked={rule.enabled}
              onCheckedChange={(v) => onChange(index, { enabled: v })}
              aria-label={t('scans.ruleList.enabledFor', '{name} enabled', { name: rule.name })}
            />
            {t('scans.approvalSettings.enabled', 'Enabled')}
          </label>
          <Button
            size="icon"
            variant="ghost"
            disabled={index === 0}
            aria-label={t('scans.ruleList.up', 'Move {name} up', { name: rule.name })}
            onClick={() => onMove(index, index - 1)}
          >
            <ArrowUp className="size-4" />
          </Button>
          <Button
            size="icon"
            variant="ghost"
            disabled={index === total - 1}
            aria-label={t('scans.ruleList.down', 'Move {name} down', { name: rule.name })}
            onClick={() => onMove(index, index + 1)}
          >
            <ArrowDown className="size-4" />
          </Button>
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('scans.ruleList.edit', 'Edit {name}', { name: rule.name })}
            onClick={() => onEdit(index)}
          >
            <Pencil className="size-4" />
          </Button>
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('scans.approvalSettings.removeRule', 'Remove rule "{name}"', {
              name: rule.name,
            })}
            onClick={() => onRemove(index)}
          >
            <Trash2 className="size-4" />
          </Button>
        </div>
      )}
    </li>
  )
}

export function ApprovalRuleList({ rules, onMove, ...rest }: ApprovalRuleListProps) {
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )
  const ids = rules.map((r, i) => r.id || `new-${i}`)
  const onDragEnd = (e: DragEndEvent) => {
    if (!e.over || e.active.id === e.over.id) return
    const from = ids.indexOf(String(e.active.id))
    const to = ids.indexOf(String(e.over.id))
    if (from >= 0 && to >= 0) onMove(from, to)
  }
  return (
    <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
      <SortableContext items={ids} strategy={verticalListSortingStrategy}>
        <ul className="divide-y rounded-md border">
          {rules.map((r, i) => (
            <RuleRow
              key={ids[i]}
              rule={r}
              index={i}
              total={rules.length}
              onMove={onMove}
              {...rest}
            />
          ))}
        </ul>
      </SortableContext>
    </DndContext>
  )
}
