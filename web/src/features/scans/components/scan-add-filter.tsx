'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { AddFilterButton } from '@/features/shared/components/filter-button'
import { ResponsivePopover } from '@/features/shared/components/responsive-popover'

/** Opens on `f` anywhere outside a text field or an open menu or dialog. */
function useAddFilterKey(onOpen: () => void) {
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'f' || e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return
      // In Query mode the filter tokens are inert: the text owns the filter.
      if (document.querySelector('[data-slot="list-toolbar-tokens"][inert]')) return
      const el = e.target as HTMLElement | null
      if (
        el?.closest?.(
          'input, textarea, select, [contenteditable="true"], [role="combobox"], [role="listbox"], [role="menu"], [role="dialog"], [role="alertdialog"]'
        )
      )
        return
      e.preventDefault()
      onOpen()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onOpen])
}

/**
 * The scans list's "Add filter": the toolbar's one filter entry from 768 px
 * (a phone opens the same filters from the Filters button joined to the
 * search field). It holds the list's filters, the few there are, in one
 * popover; a filter set here shows as a chip under the toolbar.
 */
export function ScanAddFilter({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation()
  const [open, setOpen] = React.useState(false)
  const openPicker = React.useCallback(() => setOpen(true), [])
  useAddFilterKey(openPicker)
  return (
    <ResponsivePopover
      open={open}
      onOpenChange={setOpen}
      title={t('common.addFilter.label', 'Add filter')}
      className="w-72"
      trigger={<AddFilterButton />}
    >
      <div
        data-slot="scan-add-filter"
        className="flex max-h-[min(28rem,70svh)] min-h-0 flex-col px-3 py-1"
      >
        {children}
      </div>
    </ResponsivePopover>
  )
}
