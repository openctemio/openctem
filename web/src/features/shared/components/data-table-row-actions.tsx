'use client'

import { useMemo } from 'react'
import { MoreHorizontal, type LucideIcon } from 'lucide-react'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/lib/permissions'
import { passesRouteGate, routeGate, type ApiRouteKey } from '@/lib/permissions/can-mutate'

/**
 * One item in a row-actions menu.
 */
export interface RowAction {
  label: string
  icon?: LucideIcon
  onClick: () => void
  /** Renders in destructive (red) styling, last in the menu: for Delete/Remove. */
  destructive?: boolean
  disabled?: boolean
  /**
   * Why a disabled item is unavailable (e.g. "Only the owner can…"). Shown on
   * hover or focus, and as visible text on a phone or touch screen, so the
   * action is visible but explained instead of failing with a 403.
   */
  disabledReason?: string
  /** Sets this item and the ones after it apart with a divider (e.g. before a destructive action). */
  separatorBefore?: boolean
  /** Gate this item behind a permission. Omit = always shown. */
  permission?: string | string[]
  /**
   * Gate this item behind the API route it calls (permissions and role as the
   * API checks them; see src/config/api-route-permissions.json). Prefer this
   * for actions that write.
   */
  route?: ApiRouteKey | ApiRouteKey[]
}

interface DataTableRowActionsProps {
  actions: RowAction[]
  /** Accessible label for the trigger button, e.g. "Actions for {name}". */
  label?: string
  /** The row's name: the title of the bottom sheet on a phone. */
  title?: string
}

/**
 * The canonical row "⋯" actions menu: the shared `ActionMenu` (an anchored
 * menu, or a bottom sheet on a phone when the menu is long or does not fit).
 *
 * An item gated by `permission` or `route` is hidden from a user who may not
 * use it (as the server would refuse it); an item that does not apply here is
 * disabled with its reason.
 */
export function DataTableRowActions(props: DataTableRowActionsProps) {
  // Only a menu with gated items reads the permissions (and needs their provider).
  return props.actions.some((a) => a.permission || a.route) ? (
    <GatedRowActions {...props} />
  ) : (
    <RowActionsMenu {...props} />
  )
}

function GatedRowActions({ actions, ...rest }: DataTableRowActionsProps) {
  const { permissions = [], can, isLoading, tenantRole } = usePermissions()
  const ownerOrAdmin = tenantRole === 'owner' || tenantRole === 'admin'
  const allowed = actions.filter((a) => {
    if (!a.permission && !a.route) return true
    // Hidden while permissions load, as before (owners and admins excepted).
    if (isLoading && !ownerOrAdmin) return false
    // One of the listed permissions is enough.
    const perms = a.permission === undefined ? [] : [a.permission].flat()
    if (perms.length > 0 && !perms.some((p) => can(p))) return false
    const routes = a.route === undefined ? [] : [a.route].flat()
    return routes.every((r) => passesRouteGate(routeGate(r), permissions, tenantRole))
  })
  return <RowActionsMenu actions={allowed} {...rest} />
}

function RowActionsMenu({ actions, label, title }: DataTableRowActionsProps) {
  const { t } = useTranslation()
  const items = useMemo<ActionMenuEntry[]>(() => {
    const out: ActionMenuEntry[] = []
    let section = 0
    for (const [i, a] of actions.entries()) {
      if (a.separatorBefore) section += 1
      out.push({
        id: `${i}:${a.label}`,
        label: a.label,
        icon: a.icon,
        onSelect: a.onClick,
        destructive: a.destructive,
        section: section > 0 ? String(section) : undefined,
        disabledReason: a.disabled
          ? (a.disabledReason ?? t('common.rowActions.unavailable', 'Not available right now'))
          : undefined,
      })
    }
    return out
  }, [actions, t])
  const triggerLabel = label ?? t('common.rowActions.open', 'Open row actions')
  return (
    <ActionMenu
      items={items}
      title={title ?? triggerLabel}
      label={triggerLabel}
      trigger={
        <Button variant="ghost" size="icon" aria-label={triggerLabel}>
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </Button>
      }
    />
  )
}
