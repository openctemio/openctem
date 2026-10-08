'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { Info, TriangleAlert, Wrench, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { get } from '@/lib/api/client'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

/** One platform announcement (GET /api/v1/announcements). */
export interface PlatformAnnouncement {
  id: string
  message: string
  severity: 'info' | 'warning' | 'maintenance'
  starts_at: string
  ends_at?: string
}

export const ANNOUNCEMENTS_URL = '/api/v1/announcements'
const DISMISSED_KEY = 'openctem.dismissedAnnouncements'

function readDismissed(): string[] {
  try {
    const raw = window.localStorage.getItem(DISMISSED_KEY)
    const v = raw ? (JSON.parse(raw) as unknown) : []
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(-50) : []
  } catch {
    return []
  }
}

function writeDismissed(ids: string[]) {
  try {
    window.localStorage.setItem(DISMISSED_KEY, JSON.stringify(ids.slice(-50)))
  } catch {
    // Storage unavailable: the banner comes back on the next page load.
  }
}

const STYLE = {
  maintenance: { icon: Wrench, className: 'border-warning/40 bg-warning/10' },
  warning: { icon: TriangleAlert, className: 'border-destructive/40 bg-destructive/10' },
  info: { icon: Info, className: 'border-info/40 bg-info/10' },
} as const

/**
 * The platform operator's notices (planned maintenance, warnings), shown to
 * every signed-in user under the header while they are active. The text is
 * plain and rendered as text, never HTML. A user can dismiss one; the choice
 * is kept in this browser only. Loaded once per page load (a notice is
 * written minutes or hours ahead), so it adds no polling.
 */
export function PlatformAnnouncementBanner() {
  const { t } = useTranslation()
  const { data } = useSWR<{ data: PlatformAnnouncement[] }>(
    ANNOUNCEMENTS_URL,
    (url: string) => get<{ data: PlatformAnnouncement[] }>(url),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
  const [dismissed, setDismissed] = useState<string[]>(() =>
    typeof window === 'undefined' ? [] : readDismissed()
  )
  const visible = (data?.data ?? []).filter((a) => !dismissed.includes(a.id))
  if (visible.length === 0) return null

  return (
    <div
      className="space-y-2 px-4 pt-2"
      role="region"
      aria-label={t('announcements.region', 'Announcements')}
    >
      {visible.map((a) => {
        const style = STYLE[a.severity] ?? STYLE.info
        const Icon = style.icon
        return (
          <div
            key={a.id}
            role={a.severity === 'info' ? 'status' : 'alert'}
            className={cn(
              'flex items-start gap-3 rounded-md border px-3 py-2 text-sm',
              style.className
            )}
          >
            <Icon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            <p className="min-w-0 flex-1 break-words">{a.message}</p>
            <Button
              variant="ghost"
              size="icon"
              className="size-6 shrink-0"
              aria-label={t('announcements.dismiss', 'Dismiss')}
              onClick={() => {
                const next = [...dismissed, a.id]
                setDismissed(next)
                writeDismissed(next)
              }}
            >
              <X className="size-4" />
            </Button>
          </div>
        )
      })}
    </div>
  )
}
