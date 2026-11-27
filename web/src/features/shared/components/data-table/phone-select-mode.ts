'use client'

import * as React from 'react'
import type { ActionMenuAction } from '@/components/ui/action-menu'
import { useTranslation } from '@/context/i18n-provider'
import type { DataTableSelectMode } from './data-table'

/**
 * Phone select mode held by a page that has its own More: the page puts
 * `item` first in that More (a section of its own, so a divider follows) and
 * passes `selectMode` to its `DataTable`, which then draws no More of its own
 * on the toolbar. `available` = the list shows phone cards and the user may act
 * on several rows (the table's `bulk`). One mode for every view of the page
 * (flat and grouped), so switching views keeps it.
 */
export function usePhoneSelectMode(available: boolean): {
  selectMode: DataTableSelectMode
  item: ActionMenuAction | null
} {
  const { t } = useTranslation()
  const [on, setOn] = React.useState(false)
  const selectMode = React.useMemo(() => ({ on, onChange: setOn }), [on])
  const label = t('common.table.selectMode', 'Select')
  const item = React.useMemo<ActionMenuAction | null>(
    () =>
      available
        ? {
            id: 'select',
            // Its own section: a divider (no heading) after it.
            section: 'select',
            label: on ? t('common.table.selectModeOff', 'Stop selecting') : label,
            onSelect: () => setOn(!on),
          }
        : null,
    [available, on, label, t]
  )
  return { selectMode, item }
}
