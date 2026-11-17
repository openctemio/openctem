'use client'

import { Check, Loader2, MoreHorizontal, X } from 'lucide-react'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The decision controls of one queue item: at most two direct decisions
 * (Approve, Reject) and one More menu for everything else.
 *
 * - `canDecide` false (the user lacks the permission): no decision controls.
 * - `own` (the four-eyes rule: nobody decides a request they made): the
 *   decision controls are absent and "Your request" stands in their place,
 *   with the reason on hover and focus in a table row and written out on a
 *   card (`layout="card"`).
 * - `menu`: only the items the user may use; with none, no More.
 * - `busy`: the row's own request is in flight; every control is inert and
 *   More spins.
 *
 * In a table row the two decisions are text buttons (the column stays
 * narrow); on a card they carry their icon.
 *
 * The buttons are named after the item ("Approve {name}"), so a list of
 * identical "Approve" buttons can be told apart by assistive technology.
 */
export function QueueDecisionActions({
  name,
  canDecide,
  own = false,
  ownLabel,
  ownReason,
  busy = false,
  onApprove,
  onReject,
  approveLabel,
  rejectLabel,
  menu,
  layout = 'row',
  className,
}: {
  /** The item's name, for the accessible names of its controls. */
  name: string
  canDecide: boolean
  own?: boolean
  ownLabel?: string
  ownReason?: string
  busy?: boolean
  onApprove: () => void
  onReject: () => void
  approveLabel?: string
  rejectLabel?: string
  menu?: ActionMenuEntry[]
  layout?: 'row' | 'card'
  className?: string
}) {
  const { t } = useTranslation()
  const approve = approveLabel ?? t('queue.decision.approve', 'Approve')
  const reject = rejectLabel ?? t('queue.decision.reject', 'Reject')
  const yours = ownLabel ?? t('queue.decision.own', 'Your request')
  const why = ownReason ?? t('queue.decision.ownReason', 'Someone else decides a request you made.')
  const menuLabel = t('common.actionMenu.label', 'Actions for {name}', { name })
  const items = menu ?? []
  if (!canDecide && items.length === 0) return null

  return (
    <div
      data-slot="queue-decision-actions"
      className={cn(
        'flex items-center gap-2',
        layout === 'row' ? 'justify-end' : 'justify-start',
        className
      )}
    >
      {canDecide &&
        (own ? (
          layout === 'card' ? (
            <p
              data-slot="queue-own-request"
              className="min-w-0 flex-1 text-xs text-muted-foreground"
            >
              <span className="font-medium text-foreground">{yours}</span> {why}
            </p>
          ) : (
            <Tooltip>
              <TooltipTrigger asChild>
                <span
                  data-slot="queue-own-request"
                  tabIndex={0}
                  className="rounded-sm text-xs whitespace-nowrap text-muted-foreground underline decoration-dotted underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {yours}
                  <span className="sr-only"> {why}</span>
                </span>
              </TooltipTrigger>
              <TooltipContent className="max-w-xs text-xs">{why}</TooltipContent>
            </Tooltip>
          )
        ) : (
          <>
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={onApprove}
              data-slot="queue-approve"
              aria-label={t('queue.decision.approveNamed', 'Approve {name}', { name })}
            >
              {layout === 'card' && <Check className="me-1 h-4 w-4" aria-hidden />}
              {approve}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={onReject}
              data-slot="queue-reject"
              aria-label={t('queue.decision.rejectNamed', 'Reject {name}', { name })}
            >
              {layout === 'card' && <X className="me-1 h-4 w-4" aria-hidden />}
              {reject}
            </Button>
          </>
        ))}
      {items.length > 0 && (
        <ActionMenu
          title={name}
          label={menuLabel}
          items={items}
          trigger={
            <Button
              size="icon-sm"
              variant="ghost"
              disabled={busy}
              aria-label={menuLabel}
              className={layout === 'card' ? 'ms-auto' : undefined}
            >
              {busy ? (
                <Loader2 className="animate-spin" aria-hidden />
              ) : (
                <MoreHorizontal aria-hidden />
              )}
            </Button>
          }
        />
      )}
    </div>
  )
}
