'use client'

import { Download, MoreHorizontal, RotateCcw, ShieldOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { useTranslation } from '@/context/i18n-provider'
import type { VulnActionAbilities } from './use-vuln-actions'

export interface VulnActionsMenuProps {
  /** What the actions apply to (the CVE id): the title of the phone sheet. */
  name: string
  abilities: VulnActionAbilities
  /** Why the actions on open findings are off (none open in scope), if they are. */
  blocker?: string
  busy?: boolean
  onException: () => void
  onRetest: () => void
  onExport: () => void
}

/**
 * The vulnerability page's secondary actions (request an exception, retest,
 * export) in one menu beside "Create remediation task". Hidden when the
 * caller may run none of them.
 */
export function VulnActionsMenu({
  name,
  abilities,
  blocker,
  busy,
  onException,
  onRetest,
  onExport,
}: VulnActionsMenuProps) {
  const { t } = useTranslation()
  if (!abilities.exception && !abilities.retest && !abilities.export) return null
  const items: ActionMenuEntry[] = [
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
  return (
    <ActionMenu
      title={name}
      label={t('vulnPage.actions.more', 'More actions')}
      items={items}
      trigger={
        <Button
          variant="outline"
          size="icon-sm"
          aria-label={t('vulnPage.actions.more', 'More actions')}
        >
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </Button>
      }
    />
  )
}
