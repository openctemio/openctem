'use client'

/**
 * The head of a Needs attention queue page (research/249): a back link to the
 * list of reasons, the reason as the heading that opens a menu to switch to
 * another reason (with counts), the count of this queue, the why line, and a
 * link to the same slice in the inventory. It replaces the second tab row and
 * the explanation card. Counts in the menu are requested only while it is open.
 */

import { ListCount } from '@/features/shared/components/list-title-row'
import { ArrowRight, ChevronDown, ChevronLeft, MoreHorizontal } from 'lucide-react'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { useRouter } from 'next/navigation'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTranslation } from '@/context/i18n-provider'
import { ASSET_ATTENTION_REASONS, type AttentionReasonDef } from '@/config/section-tabs'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { safeHref } from '@/lib/safe-href'
import { useAttentionCount } from './use-attention-count'
import { formatNumber } from '@/lib/app-locale'
import { useIsMobile } from '@/hooks/use-mobile'

const ATTENTION_HREF = '/assets/attention'

function MenuCount({ id }: { id: AttentionReasonDef['id'] }) {
  const count = useAttentionCount(id)
  return (
    <span className="ms-auto ps-4 text-xs text-muted-foreground tabular-nums">
      {count === undefined ? '' : formatNumber(count)}
    </span>
  )
}

interface AttentionQueueHeaderProps {
  reason: AttentionReasonDef['id']
  /** This queue's count, shown by the heading; `undefined` while loading. */
  count?: number
  /** The same slice in the inventory; absent for reasons that have no inventory view. */
  inventoryHref?: string
  /**
   * The queue's own More (e.g. "Select" on a phone); not drawn without items.
   * It ends the heading row, after the inventory link.
   */
  moreItems?: ActionMenuEntry[]
}

export function AttentionQueueHeader({
  reason,
  count,
  inventoryHref,
  moreItems,
}: AttentionQueueHeaderProps) {
  const { t } = useTranslation()
  const router = useRouter()
  const isPhone = useIsMobile()
  const visible = useVisibleSectionTabs(ASSET_ATTENTION_REASONS)
  const current = ASSET_ATTENTION_REASONS.find((r) => r.id === reason)
  if (!current) return null
  const switchTo = (href: string) => router.push(href)
  const groups = (['decide', 'fix', 'review'] as const)
    .map((g) => visible.filter((r) => r.group === g))
    .filter((rows) => rows.length > 0)
  const href = inventoryHref ? safeHref(inventoryHref) : null

  const why = t(current.whyKey, current.why)
  const inventoryLabel = t('assets.attention.openInInventory', 'Open in the inventory')
  // A phone keeps the heading row to one line: the inventory link joins the
  // queue's More there instead of wrapping onto a line of its own.
  const menuItems: ActionMenuEntry[] = [
    ...(isPhone && href
      ? [
          {
            id: 'inventory',
            label: inventoryLabel,
            // Alone it turns the trigger into the link (an icon is needed);
            // beside Select, icons for all items or none.
            icon: moreItems?.length ? undefined : ArrowRight,
            onSelect: () => router.push(href),
          },
        ]
      : []),
    ...(moreItems ?? []),
  ]

  return (
    // One row (research/249; MVP v2: no row of its own above the list): the
    // back link as an icon, the reason heading that switches reason, the
    // count, the why line (cut with an ellipsis, whole in its tooltip and at
    // the top of the reason menu), then the inventory link and the More.
    <div
      // One line on a phone: the reason name ends in an ellipsis (whole in
      // the menu) rather than push the count and More onto a line of their own.
      className="flex flex-wrap items-center gap-x-3 gap-y-2 max-md:flex-nowrap"
      data-testid="attention-queue-header"
    >
      <div className="flex min-w-0 items-center gap-1">
        <Button asChild variant="ghost" size="icon">
          <Link href={ATTENTION_HREF} aria-label={t('assets.attention.back', 'Needs attention')}>
            <ChevronLeft className="size-4 rtl:rotate-180" aria-hidden />
          </Link>
        </Button>
        <DropdownMenu>
          <h2 className="min-w-0 text-lg font-semibold">
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                title={t('assets.attention.switch', 'Switch reason')}
                // The row's control height (32, 36 on a phone): the inventory
                // link and the More share its line.
                className="inline-flex h-control max-w-full items-center gap-1.5 rounded-md px-1 text-start font-semibold outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring max-md:h-control-touch"
              >
                <span className="truncate">{t(current.labelKey, current.label)}</span>
                <ChevronDown className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              </button>
            </DropdownMenuTrigger>
          </h2>
          <DropdownMenuContent>
            <p className="px-2 py-1.5 text-xs text-muted-foreground">{why}</p>
            <DropdownMenuSeparator />
            <DropdownMenuLabel className="text-xs font-semibold text-muted-foreground">
              {t('assets.attention.switch', 'Switch reason')}
            </DropdownMenuLabel>
            <DropdownMenuRadioGroup value={reason} onValueChange={() => undefined}>
              {groups.map((rows, i) => (
                <div key={rows[0].group}>
                  {i > 0 && <DropdownMenuSeparator />}
                  {rows.map((r) => (
                    <DropdownMenuRadioItem
                      key={r.id}
                      value={r.id}
                      onSelect={() => switchTo(r.href)}
                    >
                      {t(r.labelKey, r.label)}
                      <MenuCount id={r.id} />
                    </DropdownMenuRadioItem>
                  ))}
                </div>
              ))}
            </DropdownMenuRadioGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => switchTo(ATTENTION_HREF)}>
              {t('assets.attention.allReasons', 'All reasons')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      {/* The queue's one count, as every list says it. */}
      <ListCount
        total={count ?? 0}
        loading={count === undefined}
        label={
          count === undefined
            ? undefined
            : `${formatNumber(count)} ${t(current.unitKey, current.unit, { count })}`
        }
      />
      {/* Takes what the row has left and never wraps onto a row of its own;
          a phone reads it in the reason menu. */}
      <p
        data-slot="attention-why"
        title={why}
        className="min-w-0 flex-1 basis-0 truncate text-sm text-muted-foreground max-md:hidden"
      >
        {why}
      </p>
      {((href && !isPhone) || menuItems.length > 0) && (
        <div className="ms-auto flex shrink-0 items-center gap-2">
          {href && !isPhone && (
            <Button asChild variant="outline">
              <Link href={href}>
                {inventoryLabel}
                <ArrowRight className="ms-1.5 h-3.5 w-3.5" aria-hidden />
              </Link>
            </Button>
          )}
          {menuItems.length > 0 && (
            <ActionMenu
              title={t(current.labelKey, current.label)}
              label={t('common.actionMenu.label', 'Actions for {name}', {
                name: t(current.labelKey, current.label),
              })}
              items={menuItems}
              trigger={
                <Button
                  variant="outline"
                  size="icon"
                  aria-label={t('assets.inventoryPage.moreActions', 'More actions')}
                >
                  <MoreHorizontal className="h-4 w-4" aria-hidden />
                </Button>
              }
            />
          )}
        </div>
      )}
    </div>
  )
}
