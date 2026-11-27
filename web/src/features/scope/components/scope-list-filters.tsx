'use client'

/**
 * The Filters trigger of the scope lists (entries and exclusions): Kind and
 * Status in one popover (a bottom sheet on a phone), so the toolbar keeps at
 * most two selects (the list switcher is the other) and never scrolls sideways
 * on a phone. The trigger counts the filters applied.
 */

import { useId, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { FilterPopover } from '@/features/shared/components/filter-button'
import { ScopeTargetTypeSelect } from './scope-target-type'
import type { ScopeKind } from './scope-target-type'

export interface ScopeListFiltersProps {
  kind: string
  status: string
  onKindChange: (v: string) => void
  onStatusChange: (v: string) => void
  /** The statuses the list offers, with their labels. */
  statuses: readonly { value: string; label: string }[]
  /** The kinds the list offers (default every scope kind). */
  kinds?: ScopeKind[]
}

/** How many of the two filters are applied. */
export function scopeFilterCount(kind: string, status: string): number {
  return (kind && kind !== 'all' ? 1 : 0) + (status && status !== 'all' ? 1 : 0)
}

export function ScopeListFilters({
  kind,
  status,
  onKindChange,
  onStatusChange,
  statuses,
  kinds,
}: ScopeListFiltersProps) {
  const { t } = useTranslation()
  const id = useId()
  const [open, setOpen] = useState(false)
  const count = scopeFilterCount(kind, status)
  return (
    <FilterPopover
      open={open}
      onOpenChange={setOpen}
      title={t('common.filters', 'Filters')}
      className="md:w-72"
      activeCount={count}
      data-testid="scope-filters"
    >
      <div className="flex flex-col gap-3 p-3">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${id}-kind`}>{t('scope.col.kind', 'Kind')}</Label>
          <ScopeTargetTypeSelect
            id={`${id}-kind`}
            value={kind || 'all'}
            onValueChange={onKindChange}
            withAll
            only={kinds}
            className="w-full"
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${id}-status`}>{t('scope.col.status', 'Status')}</Label>
          <Select value={status || 'all'} onValueChange={onStatusChange}>
            <SelectTrigger id={`${id}-status`} className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('scope.filter.allStatuses', 'All statuses')}</SelectItem>
              {statuses.map((s) => (
                <SelectItem key={s.value} value={s.value}>
                  {s.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {count > 0 && (
          <div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                onKindChange('all')
                onStatusChange('all')
              }}
            >
              {t('common.clearAll', 'Clear all')}
            </Button>
          </div>
        )}
      </div>
    </FilterPopover>
  )
}
