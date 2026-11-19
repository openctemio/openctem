'use client'

import { useEffect } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { safeHref } from '@/lib/safe-href'
import { useTranslation } from '@/context/i18n-provider'
import { DetailPosition } from '@/features/shared/components/detail'
import { useFindingListNav } from '../../hooks/use-finding-list-nav'
import { TYPING_TARGETS } from '../../hooks/use-drawer-navigation'
import { formatNumber } from '@/lib/app-locale'

export interface FindingPosition {
  /** The list the finding was opened from (back with its filters). */
  listHref: string
  /** That list's name. */
  listLabel: string
  /** "‹ 3 of 31 ›"; null when the finding was not opened from a list. */
  control: React.ReactNode
}

/**
 * Where a finding opened from a findings list sits in it: the list (back
 * with its filters), "n of N", and the previous and next finding (also k and
 * j). Without a list context (a direct link, or opened from a remediation
 * task, whose crumb says where it came from) there is no control and the
 * way back is the plain findings list.
 */
export function useFindingPosition(findingId: string): FindingPosition {
  const { t } = useTranslation()
  const router = useRouter()
  const fromTask = !!useSearchParams().get('from')
  const nav = useFindingListNav(fromTask ? undefined : findingId)
  // The hrefs were built from a validated list context; safeHref re-checks them
  // (same-origin paths only) where they reach a link or router.push.
  const prevHref = safeHref(nav?.prevHref, { allowRelative: true })
  const nextHref = safeHref(nav?.nextHref, { allowRelative: true })
  const returnHref = safeHref(nav?.returnPath, { allowRelative: true }) ?? '/findings'

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

  if (!nav) {
    return {
      listHref: '/findings',
      listLabel: t('findings.detail.listNav.findings', 'Findings'),
      control: null,
    }
  }
  const listLabel = nav.label || t('findings.detail.listNav.list', 'Findings list')
  return {
    listHref: returnHref,
    listLabel,
    control: (
      <DetailPosition
        label={t('findings.detail.listNav.position', '{n} of {total}', {
          n: formatNumber(nav.position),
          total: formatNumber(nav.total),
        })}
        listHref={returnHref}
        listLabel={t('findings.detail.listNav.backTo', 'Back to {list}', { list: listLabel })}
        prevHref={prevHref}
        nextHref={nextHref}
        prevLabel={t('findings.detail.listNav.prev', 'Previous finding (k)')}
        nextLabel={t('findings.detail.listNav.next', 'Next finding (j)')}
      />
    ),
  }
}
