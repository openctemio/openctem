'use client'

import {
  Copy,
  ExternalLink,
  Flag,
  Link2,
  MoreHorizontal,
  Ticket,
  Trash2,
  UserPlus,
  Wrench,
  CheckCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'

export type FindingRowAction =
  | 'view'
  | 'assign'
  | 'status'
  | 'false_positive'
  | 'create_ticket'
  | 'remediate'
  | 'copy_id'
  | 'copy_link'
  | 'delete'

interface FindingRowMenuProps {
  title: string
  onAction: (action: FindingRowAction) => void
  canCreateTicket: boolean
  canRemediate: boolean
  canDelete: boolean
}

/**
 * The row's action menu. The table row and the phone card render this one
 * component, so the two never offer different actions. Assign, status and
 * false positive need the full finding flow (assignee picker, status select
 * with its approval step), so their labels say they open it.
 */
export function FindingRowMenu({
  title,
  onAction,
  canCreateTicket,
  canRemediate,
  canDelete,
}: FindingRowMenuProps) {
  const { t } = useTranslation()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
        <Button
          variant="ghost"
          className="h-8 w-8 p-0"
          aria-label={t('findings.row.actionsFor', 'Actions for {title}', {
            title: toDisplayText(title, 80),
          })}
        >
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => onAction('view')}>
          <ExternalLink className="me-2 h-4 w-4" aria-hidden />
          {t('findings.row.viewDetails', 'View details')}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onAction('assign')}>
          <UserPlus className="me-2 h-4 w-4" aria-hidden />
          {t('findings.row.openToAssign', 'Open to assign…')}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onAction('status')}>
          <CheckCircle className="me-2 h-4 w-4" aria-hidden />
          {t('findings.row.openToChangeStatus', 'Open to change status…')}
        </DropdownMenuItem>
        {canCreateTicket && (
          <DropdownMenuItem onClick={() => onAction('create_ticket')}>
            <Ticket className="me-2 h-4 w-4" aria-hidden />
            {t('findings.header.createTicket', 'Create ticket')}
          </DropdownMenuItem>
        )}
        {canRemediate && (
          <DropdownMenuItem onClick={() => onAction('remediate')}>
            <Wrench className="me-2 h-4 w-4" aria-hidden />
            {t('remediationClaim.menu.addToRemediation')}
          </DropdownMenuItem>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => onAction('copy_id')}>
          <Copy className="me-2 h-4 w-4" aria-hidden />
          {t('findings.row.copyId', 'Copy ID')}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onAction('copy_link')}>
          <Link2 className="me-2 h-4 w-4" aria-hidden />
          {t('findings.row.copyLink', 'Copy link')}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem className="text-warning" onClick={() => onAction('false_positive')}>
          <Flag className="me-2 h-4 w-4" aria-hidden />
          {t('findings.row.openToMarkFalsePositive', 'Open to mark as false positive…')}
        </DropdownMenuItem>
        {canDelete && (
          <DropdownMenuItem className="text-destructive" onClick={() => onAction('delete')}>
            <Trash2 className="me-2 h-4 w-4" aria-hidden />
            {t('findings.row.delete', 'Delete')}
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
