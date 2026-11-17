'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { AddFilterButton, useAddFilterShortcut } from '@/features/shared/components/filter-button'
import { ResponsivePopover } from '@/features/shared/components/responsive-popover'

/**
 * The asset groups list "Add filter": the toolbar one filter entry from
 * 768 px (a phone opens the same facets from the Filters button joined to the
 * search field). It holds the list few fixed facets in one popover and opens
 * on `f`; a filter set here shows as a chip under the toolbar.
 */
export function GroupAddFilter({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation()
  const [open, setOpen] = React.useState(false)
  useAddFilterShortcut(() => setOpen(true))
  return (
    <ResponsivePopover
      open={open}
      onOpenChange={setOpen}
      title={t('common.addFilter.label', 'Add filter')}
      className="w-72"
      trigger={<AddFilterButton />}
    >
      <div
        data-slot="group-add-filter"
        className="flex max-h-[min(28rem,70svh)] min-h-0 flex-col px-3 py-1"
      >
        {children}
      </div>
    </ResponsivePopover>
  )
}
