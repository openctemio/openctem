'use client'

import { Download, MoreHorizontal, RotateCcw, ShieldOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTranslation } from '@/context/i18n-provider'
import type { VulnActionAbilities } from './use-vuln-actions'

export interface VulnActionsMenuProps {
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
  abilities,
  blocker,
  busy,
  onException,
  onRetest,
  onExport,
}: VulnActionsMenuProps) {
  const { t } = useTranslation()
  if (!abilities.exception && !abilities.retest && !abilities.export) return null
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          aria-label={t('vulnPage.actions.more', 'More actions')}
          title={t('vulnPage.actions.more', 'More actions')}
        >
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {abilities.exception && (
          <DropdownMenuItem disabled={!!blocker} onSelect={onException} title={blocker}>
            <ShieldOff className="me-2 h-4 w-4" aria-hidden />
            {t('vulnPage.actions.exception.open', 'Accept risk or mark false positive')}
          </DropdownMenuItem>
        )}
        {abilities.retest && (
          <DropdownMenuItem disabled={!!blocker} onSelect={onRetest} title={blocker}>
            <RotateCcw className="me-2 h-4 w-4" aria-hidden />
            {t('vulnPage.actions.retest.open', 'Retest open findings')}
          </DropdownMenuItem>
        )}
        {abilities.export && (
          <DropdownMenuItem disabled={busy} onSelect={onExport}>
            <Download className="me-2 h-4 w-4" aria-hidden />
            {t('vulnPage.actions.export.open', 'Export findings (CSV)')}
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
