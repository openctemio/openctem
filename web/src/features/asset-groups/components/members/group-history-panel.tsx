'use client'

/** Who joined and left a group, and why, newest first. */

import { useState } from 'react'
import Link from 'next/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useGroupHistoryApi } from '../../api/use-group-rule-api'

const PAGE_SIZE = 20

export function GroupHistoryPanel({ groupId }: { groupId: string }) {
  const { t, locale } = useTranslation()
  const [page, setPage] = useState(1)
  const { data, isLoading } = useGroupHistoryApi(groupId, page, PAGE_SIZE)
  const when = (iso: string) =>
    new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(
      new Date(iso)
    )

  if (isLoading && !data) {
    return <Skeleton className="h-40 w-full" />
  }
  if (!data || data.data.length === 0) {
    return (
      <p
        className="py-8 text-center text-sm text-muted-foreground"
        data-testid="group-history-empty"
      >
        {t('assetGroups.members.history.empty', 'Nobody has joined or left this group yet.')}
      </p>
    )
  }
  return (
    <div className="space-y-3" data-testid="group-history">
      <ul className="divide-y rounded-lg border">
        {data.data.map((e) => (
          <li key={e.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
            <Badge variant="outline">
              {e.action === 'joined'
                ? t('assetGroups.members.history.joined', 'Joined')
                : t('assetGroups.members.history.left', 'Left')}
            </Badge>
            <Link
              href={`/assets/${e.asset_id}`}
              className="min-w-0 truncate font-medium hover:underline"
            >
              {e.asset_name || e.asset_id}
            </Link>
            <span className="text-muted-foreground">
              {t(`assetGroups.members.history.reason.${e.reason}`, e.reason)}
            </span>
            <time
              dateTime={e.created_at}
              className="ms-auto text-xs tabular-nums text-muted-foreground"
            >
              {when(e.created_at)}
            </time>
          </li>
        ))}
      </ul>
      {data.total_pages > 1 ? (
        <div className="flex items-center justify-between">
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={page <= 1}
            onClick={() => setPage(page - 1)}
          >
            {t('assetGroups.members.history.previous', 'Previous')}
          </Button>
          <span className="text-xs text-muted-foreground">
            {t('assetGroups.members.history.page', 'Page {page} of {pages}', {
              page: data.page,
              pages: data.total_pages,
            })}
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={page >= data.total_pages}
            onClick={() => setPage(page + 1)}
          >
            {t('assetGroups.members.history.next', 'Next')}
          </Button>
        </div>
      ) : null}
    </div>
  )
}
