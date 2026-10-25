'use client'

import { useEffect } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useFindingListNav } from '../../hooks/use-finding-list-nav'
import { TYPING_TARGETS } from '../../hooks/use-drawer-navigation'

/**
 * "Findings › Open P0 and P1   ‹ 3 of 31 ›" above a finding opened from a
 * findings list: the list it came from (back with its filters), where the
 * finding sits in it, and the previous and next finding (also j and k).
 * Renders nothing when the finding was not opened from a list.
 */
export function FindingListCrumb({ findingId }: { findingId: string }) {
  const { t } = useTranslation()
  const router = useRouter()
  // Opened from a remediation task: the task crumb says where it came from.
  const fromTask = !!useSearchParams().get('from')
  const nav = useFindingListNav(fromTask ? undefined : findingId)
  const prevHref = nav?.prevHref
  const nextHref = nav?.nextHref

  useEffect(() => {
    if (!prevHref && !nextHref) return
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return
      if (e.key !== 'j' && e.key !== 'k') return
      const el = e.target as HTMLElement | null
      if (el?.closest?.(TYPING_TARGETS) || document.querySelector('[role="dialog"]')) return
      const href = e.key === 'j' ? nextHref : prevHref
      if (!href) return
      e.preventDefault()
      router.push(href)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [prevHref, nextHref, router])

  if (!nav) return null
  const label = nav.label || t('findings.detail.listNav.list', 'Findings list')
  return (
    <div
      data-slot="finding-list-crumb"
      className="mb-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 text-sm"
    >
      <nav
        aria-label={t('findings.detail.listNav.aria', 'List this finding was opened from')}
        className="text-muted-foreground flex min-w-0 items-center gap-1"
      >
        <Link href="/findings" className="hover:text-foreground shrink-0 hover:underline">
          {t('findings.detail.listNav.findings', 'Findings')}
        </Link>
        <ChevronRight className="size-3.5 shrink-0 rtl:rotate-180" aria-hidden />
        <Link
          href={nav.returnPath}
          className="text-foreground min-w-0 truncate font-medium hover:underline"
        >
          {label}
        </Link>
        <span className="tabular-nums">{nav.total.toLocaleString()}</span>
      </nav>
      <div className="flex items-center gap-1">
        <Button
          asChild={!!prevHref}
          variant="ghost"
          size="icon"
          className="size-8"
          disabled={!prevHref}
          aria-label={t('findings.detail.listNav.prev', 'Previous finding (k)')}
        >
          {prevHref ? (
            <Link href={prevHref}>
              <ChevronLeft className="size-4 rtl:rotate-180" aria-hidden />
            </Link>
          ) : (
            <ChevronLeft className="size-4 rtl:rotate-180" aria-hidden />
          )}
        </Button>
        <span className="text-muted-foreground px-1 tabular-nums" aria-live="polite">
          {t('findings.detail.listNav.position', '{n} of {total}', {
            n: nav.position.toLocaleString(),
            total: nav.total.toLocaleString(),
          })}
        </span>
        <Button
          asChild={!!nextHref}
          variant="ghost"
          size="icon"
          className="size-8"
          disabled={!nextHref}
          aria-label={t('findings.detail.listNav.next', 'Next finding (j)')}
        >
          {nextHref ? (
            <Link href={nextHref}>
              <ChevronRight className="size-4 rtl:rotate-180" aria-hidden />
            </Link>
          ) : (
            <ChevronRight className="size-4 rtl:rotate-180" aria-hidden />
          )}
        </Button>
      </div>
    </div>
  )
}
