'use client'

import type { MouseEvent, ReactNode } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { SeverityBadge } from '@/features/shared'
import type { MobileRowSelection } from '@/features/shared'
import type { Finding } from '@/features/findings'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import { FindingSubStatus } from '@/features/findings/components/lifecycle/finding-sub-status'
import { ExploitSignals } from '@/features/findings/components/exploit-signals'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { SlaDueChip } from '@/features/sla/components/sla-due-chip'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { maskSensitiveText } from '@/lib/mask-sensitive'
import { findingRowTone } from '@/features/findings/lib/row-tone'
import { BranchOnlyBadge } from '@/features/findings/components/branch-only-badge'
import { AssetMarkers } from '@/features/findings/components/cells/asset-markers'
import { DuplicatesChip } from '@/features/findings/components/cells/duplicates-chip'
import { FindingRowId } from '@/features/findings/components/cells/finding-row-id'
import { FindingTitleCell } from '@/features/findings/components/cells/finding-title-cell'

interface FindingPhoneCardProps {
  finding: Finding
  selection: MobileRowSelection
  onOpen: (finding: Finding) => void
  /** The row menu; the same component the table row renders. */
  menu: ReactNode
}

/** The card's own controls: a tap on one never opens the finding as well. */
const CONTROL_SELECTOR =
  'button, a[href], input, label, [role="checkbox"], [role="menuitem"], [tabindex="0"]'

/**
 * A finding on a phone (list and grouped views alike), top to bottom: the
 * priority with the row menu at the end of its line (and the checkbox in
 * select mode); the title on up to two lines; the asset and the place on it,
 * one line; the id (the CVE, else the rule) and the time left; the severity,
 * the status and the exploit mark, then the branch-only and duplicates marks
 * when the finding has them. A tap anywhere on the card opens the finding; the title is
 * the link that does so from the keyboard, named by the whole title. The
 * checkbox and the menu are separate targets, so a tap on one never opens
 * the finding and a tap on the body never changes the selection.
 * Its text is masked like a table row's (maskSensitiveText): no secret or
 * e-mail address in clear, no "Show".
 */
export function FindingPhoneCard({ finding: f, selection, onOpen, menu }: FindingPhoneCardProps) {
  const { t } = useTranslation()
  const hasDue = !!f.slaDeadline && !!f.slaStatus && f.slaStatus !== 'not_applicable'
  const hasId = !!(f.cve ?? '').trim() || !!(f.ruleId ?? '').trim()
  const open = (e: MouseEvent<HTMLDivElement>) => {
    const target = e.target as HTMLElement
    // A menu or sheet opened from the card is drawn outside it.
    if (!e.currentTarget.contains(target) || target.closest(CONTROL_SELECTOR)) return
    onOpen(f)
  }
  return (
    <div
      data-testid="finding-phone-card"
      data-slot="finding-phone-card"
      data-state={selection.selected ? 'selected' : undefined}
      data-tone={findingRowTone(f)}
      onClick={open}
      className="flex w-full cursor-pointer flex-col gap-1 px-3 pt-1 pb-3 transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted"
    >
      {/* Priority is the queue order, so it leads the card. The line is as
          tall as a touch target, which the checkbox and the menu fill. */}
      <div data-slot="finding-card-head" className="flex h-touch-target items-center gap-2">
        {selection.selectable && (
          <label
            data-slot="finding-card-select"
            className="-ms-3 flex size-touch-target shrink-0 cursor-pointer items-center justify-center"
          >
            <Checkbox
              checked={selection.selected}
              onCheckedChange={(v) => selection.onSelectedChange(!!v)}
              aria-label={t('findings.list.selectRow', 'Select finding {title}', {
                title: toDisplayText(maskSensitiveText(f.title), 80),
              })}
            />
          </label>
        )}
        <PriorityClassBadge priorityClass={f.priorityClass} />
        <div data-slot="finding-card-menu" className="-me-1 ms-auto flex shrink-0 items-center">
          {menu}
        </div>
      </div>
      <FindingTitleCell
        className="gap-0.5 text-sm"
        titleLines={2}
        title={f.title}
        onOpen={() => onOpen(f)}
        findingId={f.id}
        openLabel={t('findings.list.openRow', '{title}, view details', {
          title: toDisplayText(f.title, 500),
        })}
        target={f.location?.full}
        markers={
          <AssetMarkers
            interactive={false}
            internetFacing={f.assets[0]?.isInternetAccessible}
            crownJewel={f.assets[0]?.isCrownJewel}
          />
        }
      />
      {(hasId || hasDue) && (
        <div data-slot="finding-card-meta" className="flex min-w-0 items-center gap-3">
          <FindingRowId cve={f.cve} ruleId={f.ruleId} className="max-w-none min-w-0 shrink" />
          {hasDue && (
            <SlaDueChip
              status={f.slaStatus}
              deadline={f.slaDeadline}
              kevCapped={f.slaKevCapped}
              className="shrink-0"
            />
          )}
        </div>
      )}
      <div data-slot="finding-card-state" className="mt-0.5 flex flex-wrap items-center gap-1.5">
        <SeverityBadge severity={f.severity} />
        <FindingStatusBadge status={f.status} />
        <FindingSubStatus subStatusId={f.subStatusId} />
        {/* At most one exploit chip on a phone row: KEV, else EPSS from 10%. */}
        <ExploitSignals
          variant="compact"
          isInKev={f.isInKev}
          kevDueDate={f.kevDueDate}
          kevRansomware={f.kevRansomware}
          epssScore={f.epssScore}
        />
        {f.branchOnly && <BranchOnlyBadge />}
        <DuplicatesChip count={f.duplicatesMarked} interactive={false} />
      </div>
    </div>
  )
}
