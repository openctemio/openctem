'use client'

import { Download, RotateCcw, ShieldOff } from 'lucide-react'
import type { ActionMenuEntry } from '@/components/ui/action-menu'
import { useTranslation } from '@/context/i18n-provider'
import type { VulnActionAbilities } from './use-vuln-actions'

export interface VulnActionEntriesProps {
  abilities: VulnActionAbilities
  /** Why the actions on open findings are off (none open in scope), if they are. */
  blocker?: string
  busy?: boolean
  onException: () => void
  onRetest: () => void
  onExport: () => void
}

/**
 * The vulnerability page's further actions (request an exception, retest,
 * export) as the More menu entries of the page header. Only the ones the
 * caller may run; none at all hides the menu.
 */
export function useVulnActionEntries({
  abilities,
  blocker,
  busy,
  onException,
  onRetest,
  onExport,
}: VulnActionEntriesProps): ActionMenuEntry[] {
  const { t } = useTranslation()
  return [
    ...(abilities.exception
      ? [
          {
            id: 'exception',
            label: t('vulnPage.actions.exception.open', 'Accept risk or mark false positive'),
            icon: ShieldOff,
            disabledReason: blocker,
            onSelect: onException,
          },
        ]
      : []),
    ...(abilities.retest
      ? [
          {
            id: 'retest',
            label: t('vulnPage.actions.retest.open', 'Retest open findings'),
            icon: RotateCcw,
            disabledReason: blocker,
            onSelect: onRetest,
          },
        ]
      : []),
    ...(abilities.export
      ? [
          {
            id: 'export',
            label: t('vulnPage.actions.export.open', 'Export findings (CSV)'),
            icon: Download,
            disabledReason: busy ? t('vulnPage.actions.busy', 'Working...') : undefined,
            onSelect: onExport,
          },
        ]
      : []),
  ]
}
