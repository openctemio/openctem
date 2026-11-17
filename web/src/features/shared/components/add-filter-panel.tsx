'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { AddFilterButton, useAddFilterShortcut } from './filter-button'
import { ResponsivePopover } from './responsive-popover'

export interface AddFilterPanelProps {
  /** The list's facet sections (e.g. a `FacetPanel`), drawn in a scrolling body. */
  children: React.ReactNode
  /** Popover title and the trigger's name. Defaults to "Add filter". */
  title?: string
}

/**
 * "Add filter" for a list whose filters are a handful of fixed facets (no
 * field registry): the shared `AddFilterButton` opening the facets in one
 * popover (a sheet on a phone), with the `f` shortcut. A filter set here shows
 * as a chip under the toolbar. It is the toolbar's one filter entry from
 * 768 px; a phone opens the same facets from the Filters button joined to the
 * search field.
 */
export function AddFilterPanel({ children, title }: AddFilterPanelProps) {
  const { t } = useTranslation()
  const [open, setOpen] = React.useState(false)
  useAddFilterShortcut(() => setOpen(true))
  return (
    <ResponsivePopover
      open={open}
      onOpenChange={setOpen}
      title={title ?? t('common.addFilter.label', 'Add filter')}
      className="w-72"
      trigger={<AddFilterButton />}
    >
      <div
        data-slot="add-filter-panel"
        className="flex max-h-[min(28rem,70svh)] min-h-0 flex-col px-3 py-1"
      >
        {children}
      </div>
    </ResponsivePopover>
  )
}
