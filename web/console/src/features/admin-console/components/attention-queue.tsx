'use client'

import Link from '@/components/link'
import { AlertTriangle, ArrowRight, CircleCheck, Info, OctagonAlert } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { safeHref } from '@/lib/safe-href'
import type { AttentionItem, AttentionSeverity } from '../lib/attention'

const SEVERITY: Record<
  AttentionSeverity,
  { icon: typeof Info; className: string; labelKey: string }
> = {
  critical: {
    icon: OctagonAlert,
    className: 'text-destructive',
    labelKey: 'admin.attention.critical',
  },
  warning: {
    icon: AlertTriangle,
    className: 'text-warning',
    labelKey: 'admin.attention.warning',
  },
  info: { icon: Info, className: 'text-info', labelKey: 'admin.attention.info' },
}

/**
 * The console overview's "what needs me now" list: one row per problem, most
 * severe first, each with its one-click action when a console page handles it.
 */
export function AttentionQueue({
  items,
  isLoading,
}: {
  items: AttentionItem[]
  isLoading?: boolean
}) {
  const { t } = useTranslation()

  if (isLoading) {
    return (
      <div className="space-y-2" aria-busy="true">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
    )
  }

  if (items.length === 0) {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 py-6">
          <CircleCheck className="size-5 shrink-0 text-success" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium">{t('admin.attention.clear', 'All clear')}</p>
            <p className="text-sm text-muted-foreground">
              {t(
                'admin.attention.clearDetail',
                'Nothing needs an administrator right now. This list refreshes every minute.'
              )}
            </p>
          </div>
        </CardContent>
      </Card>
    )
  }

  // One bordered list with a divider per item: a problem is a row, not a
  // card, so eight problems still leave the numbers on the first screen. A
  // problem a console page handles is one link, the whole row: its words and
  // the action's name with an arrow at the end, so the row never holds a
  // lone button under its text.
  return (
    <ul
      className="divide-y overflow-hidden rounded-lg border bg-card"
      aria-label={t('admin.attention.heading', 'Needs attention')}
    >
      {items.map((item) => {
        const sev = SEVERITY[item.severity]
        const Icon = sev.icon
        const href = item.href && item.actionKey ? safeHref(item.href) : undefined
        const body = (
          <>
            <Icon className={cn('mt-0.5 size-4 shrink-0', sev.className)} aria-hidden="true" />
            <span className="flex min-w-0 flex-1 flex-col">
              <span className="text-sm font-medium">
                <span className="sr-only">{t(sev.labelKey)}: </span>
                {t(item.titleKey, item.title, item.vars)}
              </span>
              <span className="text-sm text-muted-foreground">
                {t(item.detailKey, item.detail, item.vars)}
              </span>
            </span>
          </>
        )
        return (
          <li key={item.id} data-severity={item.severity}>
            {href && item.actionKey ? (
              <Link
                href={href}
                data-slot="attention-item"
                className="flex items-start gap-3 px-4 py-3 outline-none hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
              >
                {body}
                <span className="flex shrink-0 items-center gap-1 self-center text-sm font-medium text-primary">
                  {t(item.actionKey, item.action)}
                  <ArrowRight className="size-4 rtl:rotate-180" aria-hidden="true" />
                </span>
              </Link>
            ) : (
              <div data-slot="attention-item" className="flex items-start gap-3 px-4 py-3">
                {body}
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
