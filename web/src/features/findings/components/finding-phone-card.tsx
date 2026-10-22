'use client'

import type { ReactNode } from 'react'
import { ChevronRight } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { SeverityBadge } from '@/features/shared'
import type { MobileRowSelection } from '@/features/shared'
import type { Finding } from '@/features/findings'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import { FindingSubStatus } from '@/features/findings/components/lifecycle/finding-sub-status'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { BranchOnlyBadge } from '@/features/findings/components/branch-only-badge'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { middleEllipsis } from '@/lib/middle-ellipsis'
import { cn } from '@/lib/utils'

interface FindingPhoneCardProps {
  finding: Finding
  selection: MobileRowSelection
  onOpen: (finding: Finding) => void
  /** The row menu; the same component the table row renders. */
  menu: ReactNode
}

/**
 * A finding on a phone (list and grouped views alike): the same selection
 * checkbox and action menu the table row has, around a button that opens the
 * finding. Selecting a card is a separate control from opening it, so a tap
 * on the body never changes the selection.
 */
export function FindingPhoneCard({ finding: f, selection, onOpen, menu }: FindingPhoneCardProps) {
  const { t } = useTranslation()
  const title = toDisplayText(f.title, 500)
  return (
    <div
      data-testid="finding-phone-card"
      data-state={selection.selected ? 'selected' : undefined}
      className={cn(
        'flex w-full items-start gap-1 ps-3 pe-1 transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted'
      )}
    >
      {selection.selectable && (
        <div className="flex h-10 shrink-0 items-center pt-2">
          <Checkbox
            checked={selection.selected}
            onCheckedChange={(v) => selection.onSelectedChange(!!v)}
            aria-label={t('findings.list.selectRow', 'Select finding {title}', {
              title: toDisplayText(f.title, 80),
            })}
          />
        </div>
      )}
      <button
        type="button"
        onClick={() => onOpen(f)}
        className="flex min-w-0 flex-1 items-start gap-3 py-3 text-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <SeverityBadge severity={f.severity} className="mt-0.5 shrink-0" />
        <div className="min-w-0 flex-1">
          <p dir="auto" className="line-clamp-2 text-sm font-medium [unicode-bidi:isolate]">
            {title}
          </p>
          {(f.cve || f.scanner) && (
            <p className="mt-0.5 truncate text-xs text-muted-foreground">
              {f.cve && <span className="font-mono">{f.cve}</span>}
              {f.cve && f.scanner && ' · '}
              {f.scanner}
            </p>
          )}
          {f.location?.asset && (
            <p dir="auto" className="mt-0.5 truncate text-xs [unicode-bidi:isolate]">
              {toDisplayText(f.location.asset, 500)}
            </p>
          )}
          {f.location?.detail && (
            <p
              dir="auto"
              className="truncate font-mono text-xs text-muted-foreground [unicode-bidi:isolate]"
            >
              {middleEllipsis(toDisplayText(f.location.detail, 2000), 28)}
            </p>
          )}
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {f.priorityClass && <PriorityClassBadge priorityClass={f.priorityClass} />}
            <FindingStatusBadge status={f.status} />
            <FindingSubStatus subStatusId={f.subStatusId} />
            {f.branchOnly && <BranchOnlyBadge />}
            {f.isInKev && (
              <Badge variant="destructive" className="h-5 px-1.5 text-[10px]">
                {t('findings.list.kev', 'KEV')}
              </Badge>
            )}
          </div>
        </div>
        <ChevronRight
          className="mt-1 h-4 w-4 shrink-0 text-muted-foreground rtl:rotate-180"
          aria-hidden
        />
      </button>
      <div className="flex h-10 shrink-0 items-center pt-2">{menu}</div>
    </div>
  )
}
