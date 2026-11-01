'use client'

/**
 * The head of a Needs attention queue page (research/249): a back link to the
 * list of reasons, the reason as the heading that opens a menu to switch to
 * another reason (with counts), the count of this queue, the why line, and a
 * link to the same slice in the inventory. It replaces the second tab row and
 * the explanation card. Counts in the menu are requested only while it is open.
 */

import { ArrowRight, ChevronDown, ChevronLeft } from 'lucide-react'
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

const ATTENTION_HREF = '/assets/attention'

function MenuCount({ id }: { id: AttentionReasonDef['id'] }) {
  const count = useAttentionCount(id)
  return (
    <span className="ms-auto ps-4 text-xs text-muted-foreground tabular-nums">
      {count === undefined ? '' : count.toLocaleString()}
    </span>
  )
}

interface AttentionQueueHeaderProps {
  reason: AttentionReasonDef['id']
  /** This queue's count, shown by the heading; `undefined` while loading. */
  count?: number
  /** The same slice in the inventory; absent for reasons that have no inventory view. */
  inventoryHref?: string
}

export function AttentionQueueHeader({ reason, count, inventoryHref }: AttentionQueueHeaderProps) {
  const { t } = useTranslation()
  const router = useRouter()
  const visible = useVisibleSectionTabs(ASSET_ATTENTION_REASONS)
  const current = ASSET_ATTENTION_REASONS.find((r) => r.id === reason)
  if (!current) return null
  const switchTo = (href: string) => router.push(href)
  const groups = (['decide', 'fix', 'review'] as const)
    .map((g) => visible.filter((r) => r.group === g))
    .filter((rows) => rows.length > 0)
  const href = inventoryHref ? safeHref(inventoryHref) : null

  return (
    <div className="flex flex-col gap-2" data-testid="attention-queue-header">
      <Link
        href={ATTENTION_HREF}
        className="inline-flex w-fit items-center gap-1 rounded-sm text-sm text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
      >
        <ChevronLeft className="size-3.5 rtl:rotate-180" aria-hidden />
        {t('assets.attention.back', 'Needs attention')}
      </Link>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <DropdownMenu>
          <h2 className="text-lg font-semibold">
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                title={t('assets.attention.switch', 'Switch reason')}
                className="-ms-1 inline-flex items-center gap-1.5 rounded-md px-1 py-0.5 text-start font-semibold outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
              >
                {t(current.labelKey, current.label)}
                <ChevronDown className="size-4 text-muted-foreground" aria-hidden />
              </button>
            </DropdownMenuTrigger>
          </h2>
          <DropdownMenuContent align="start" className="min-w-64">
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
        {count !== undefined && (
          <span className="text-sm text-muted-foreground" data-testid="attention-queue-count">
            {count.toLocaleString()} {t(current.unitKey, current.unit, { count })}
          </span>
        )}
        {href && (
          <Button asChild variant="outline" size="sm" className="ms-auto">
            <Link href={href}>
              {t('assets.attention.openInInventory', 'Open in the inventory')}
              <ArrowRight className="ms-1.5 h-3.5 w-3.5" aria-hidden />
            </Link>
          </Button>
        )}
      </div>
      <p className="text-sm text-muted-foreground">{t(current.whyKey, current.why)}</p>
    </div>
  )
}
