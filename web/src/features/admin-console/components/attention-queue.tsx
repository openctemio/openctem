'use client'

import Link from '@/components/link'
import { AlertTriangle, ArrowRight, CircleCheck, Info, OctagonAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { safeHref } from '@/lib/safe-href'
import type { AttentionItem, AttentionSeverity } from '../lib/attention'

const SEVERITY: Record<
  AttentionSeverity,
  { icon: typeof Info; className: string; labelKey: string; label: string }
> = {
  critical: {
    icon: OctagonAlert,
    className: 'text-destructive',
    labelKey: 'admin.attention.critical',
    label: 'Critical',
  },
  warning: {
    icon: AlertTriangle,
    className: 'text-warning',
    labelKey: 'admin.attention.warning',
    label: 'Warning',
  },
  info: { icon: Info, className: 'text-info', labelKey: 'admin.attention.info', label: 'Info' },
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

  return (
    <ul className="space-y-2" aria-label={t('admin.attention.heading', 'Needs attention')}>
      {items.map((item) => {
        const sev = SEVERITY[item.severity]
        const Icon = sev.icon
        return (
          <li key={item.id}>
            <Card className="py-0">
              <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
                <div className="flex min-w-0 flex-1 items-start gap-3">
                  <Icon
                    className={cn('mt-0.5 size-5 shrink-0', sev.className)}
                    aria-hidden="true"
                  />
                  <div className="min-w-0">
                    <p className="text-sm font-medium">
                      <span className="sr-only">{t(sev.labelKey, sev.label)}: </span>
                      {t(item.titleKey, item.title, item.vars)}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      {t(item.detailKey, item.detail, item.vars)}
                    </p>
                  </div>
                </div>
                {item.href && item.actionKey && (
                  <Button
                    asChild
                    variant="outline"
                    size="sm"
                    className="shrink-0 self-start sm:self-center"
                  >
                    <Link href={safeHref(item.href) ?? '/admin'}>
                      {t(item.actionKey, item.action)}
                      <ArrowRight className="ms-1 size-4" />
                    </Link>
                  </Button>
                )}
              </CardContent>
            </Card>
          </li>
        )
      })}
    </ul>
  )
}
