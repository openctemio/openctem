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
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import {
  ROW_MENU_REASON_FALLBACK,
  rowMenuBlocks,
  type RowMenuFinding,
  type RowMenuGatedAction,
} from '../lib/row-menu-state'

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
  /**
   * The row's state (status, source, linked tickets): an item that does not
   * apply to it is shown disabled with the reason.
   */
  finding: RowMenuFinding
  /** Trigger size: dense (28) in a table row, the default; `icon` on a phone card. */
  size?: 'icon-sm' | 'icon'
  onAction: (action: FindingRowAction) => void
  /** May assign this finding (the drawer's assignee picker); hides "Open to assign…" otherwise. */
  canAssign: boolean
  /** May change its status (the drawer's status select, false positive included). */
  canChangeStatus: boolean
  canCreateTicket: boolean
  canRemediate: boolean
  canDelete: boolean
}

/**
 * The row's action menu. The table row and the phone card render this one
 * component, so the two never offer different actions. Assign, status and
 * false positive need the full finding flow (assignee picker, status select
 * with its approval step), so their labels say they open it; each is offered
 * only to someone the API lets make that change (hidden otherwise). An item
 * that does not apply to this finding's state stays in its place, disabled,
 * with the reason (`rowMenuBlocks`); nothing is disabled without one.
 */
export function FindingRowMenu({
  title,
  finding,
  size = 'icon-sm',
  onAction,
  canAssign,
  canChangeStatus,
  canCreateTicket,
  canRemediate,
  canDelete,
}: FindingRowMenuProps) {
  const { t } = useTranslation()
  const act = (action: FindingRowAction) => () => onAction(action)
  const blocks = rowMenuBlocks(finding)
  const reason = (action: RowMenuGatedAction) => {
    const code = blocks[action]
    return code ? t(`findings.row.reason.${code}`, ROW_MENU_REASON_FALLBACK[code]) : undefined
  }
  const items: ActionMenuEntry[] = [
    {
      id: 'view',
      label: t('findings.row.viewDetails', 'View details'),
      icon: ExternalLink,
      onSelect: act('view'),
    },
    ...(canAssign
      ? [
          {
            id: 'assign',
            label: t('findings.row.openToAssign', 'Open to assign…'),
            icon: UserPlus,
            onSelect: act('assign'),
            disabledReason: reason('assign'),
          },
        ]
      : []),
    ...(canChangeStatus
      ? [
          {
            id: 'status',
            label: t('findings.row.openToChangeStatus', 'Open to change status…'),
            icon: CheckCircle,
            onSelect: act('status'),
            disabledReason: reason('status'),
          },
        ]
      : []),
    ...(canCreateTicket
      ? [
          {
            id: 'create_ticket',
            label: t('findings.header.createTicket', 'Create ticket'),
            icon: Ticket,
            onSelect: act('create_ticket'),
            disabledReason: reason('create_ticket'),
          },
        ]
      : []),
    ...(canRemediate
      ? [
          {
            id: 'remediate',
            label: t('remediationClaim.menu.addToRemediation'),
            icon: Wrench,
            onSelect: act('remediate'),
          },
        ]
      : []),
    {
      id: 'copy_id',
      section: 'copy',
      label: t('findings.row.copyId', 'Copy ID'),
      icon: Copy,
      onSelect: act('copy_id'),
    },
    {
      id: 'copy_link',
      section: 'copy',
      label: t('findings.row.copyLink', 'Copy link'),
      icon: Link2,
      onSelect: act('copy_link'),
    },
    ...(canChangeStatus
      ? [
          {
            id: 'false_positive',
            section: 'dismiss',
            label: t('findings.row.openToMarkFalsePositive', 'Open to mark as false positive…'),
            icon: Flag,
            onSelect: act('false_positive'),
            disabledReason: reason('false_positive'),
          },
        ]
      : []),
    ...(canDelete
      ? [
          {
            id: 'delete',
            label: t('findings.row.delete', 'Delete'),
            icon: Trash2,
            destructive: true,
            onSelect: act('delete'),
          },
        ]
      : []),
  ]
  const name = toDisplayText(title, 80)
  const label = t('findings.row.actionsFor', 'Actions for {title}', { title: name })
  return (
    <ActionMenu
      items={items}
      title={name}
      label={label}
      trigger={
        // Literal sizes: the icon-button guard reads them statically.
        size === 'icon' ? (
          <Button size="icon" variant="ghost" aria-label={label}>
            <MoreHorizontal className="h-4 w-4" aria-hidden />
          </Button>
        ) : (
          <Button size="icon-sm" variant="ghost" aria-label={label}>
            <MoreHorizontal className="h-4 w-4" aria-hidden />
          </Button>
        )
      }
    />
  )
}
