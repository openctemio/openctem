'use client'

import type { ReactNode } from 'react'
import { ChevronRight } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import { SeverityBadge } from '@/features/shared'
import type { MobileRowSelection } from '@/features/shared'
import type { Finding } from '@/features/findings'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import { FindingSubStatus } from '@/features/findings/components/lifecycle/finding-sub-status'
import { ExploitSignals } from '@/features/findings/components/exploit-signals'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { BranchOnlyBadge } from '@/features/findings/components/branch-only-badge'
import { MetaLine } from '@/features/shared/components/text-layout'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { findingRowTone } from '@/features/findings/lib/row-tone'
import { AssetMarkers } from '@/features/findings/components/cells/asset-markers'
import { DuplicatesChip } from '@/features/findings/components/cells/duplicates-chip'
import { FindingTitleCell } from '@/features/findings/components/cells/finding-title-cell'

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
  return (
    <div
      data-testid="finding-phone-card"
      data-state={selection.selected ? 'selected' : undefined}
      data-tone={findingRowTone(f)}
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
        {/* Priority is the queue order, so it leads the card (left slot). */}
        <PriorityClassBadge priorityClass={f.priorityClass} className="mt-0.5" />
        <div className="min-w-0 flex-1">
          <FindingTitleCell
            className="gap-0.5 text-sm"
            titleLines={2}
            title={f.title}
            target={f.location?.full}
            markers={
              <AssetMarkers
                interactive={false}
                internetFacing={f.assets[0]?.isInternetAccessible}
                crownJewel={f.assets[0]?.isCrownJewel}
              />
            }
            meta={
              (f.cve || f.scanner) && (
                <MetaLine
                  items={[f.cve && <span className="font-mono">{f.cve}</span>, f.scanner]}
                />
              )
            }
          />
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={f.severity} />
            <FindingStatusBadge status={f.status} />
            <FindingSubStatus subStatusId={f.subStatusId} />
            {f.branchOnly && <BranchOnlyBadge />}
            {/* At most one exploit chip on a phone row: KEV, else EPSS from 10%. */}
            <ExploitSignals
              variant="compact"
              isInKev={f.isInKev}
              kevDueDate={f.kevDueDate}
              kevRansomware={f.kevRansomware}
              epssScore={f.epssScore}
            />
            <DuplicatesChip count={f.duplicatesMarked} interactive={false} />
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
