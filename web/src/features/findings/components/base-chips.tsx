'use client'

import { FilterSelect } from '@/features/shared/components/filter-select'
import { useTranslation } from '@/context/i18n-provider'
import type { PracticeCounts } from '../api/use-practice-counts'
import {
  PRACTICE_VIEW_TEXT,
  practiceLabelKey,
  practiceTabs,
  type PracticeView,
} from '../lib/practice'
import { FINDING_LENSES, lensLabelKey, type FindingLens } from '../lib/state-lens'

interface FindingsBaseChipsProps {
  practice: PracticeView
  /** Which practices hold findings (the list's include=practice_counts); never shown as numbers. */
  practiceCounts?: PracticeCounts
  /** The open saved view sets the practice itself (no `practice` in the URL). */
  practiceFromView?: boolean
  onPracticeChange: (view: PracticeView) => void
  lens: FindingLens
  /** The open saved view sets the status scope itself (no `state` in the URL). */
  lensFromView?: boolean
  onLensChange: (lens: FindingLens) => void
  /**
   * Drawn at the top of the filter sheet, which is what the filter button
   * opens under 1024 px; the toolbar ones hide under 768 px and on a toolbar
   * narrower than 42rem (a 768 px tablet: with both chips the toolbar wrapped
   * "Open" onto a row of its own).
   */
  inSheet?: boolean
}

const TOOLBAR_ONLY_WHEN_ROOM = 'max-md:hidden @max-[42rem]/toolbar:hidden'

/**
 * The two fixed scopes of the findings list, first after the search: Practice
 * (Vulnerabilities by default) and State (Open by default). They are never
 * removed, only changed, and carry no counts (the count shows once, beside the
 * view name). The practice menu lists Vulnerabilities, Compliance, each other
 * practice that holds findings, and All. While a saved view sets a scope
 * itself, the chip reads "Set by the view" until one is picked. Each chip
 * keeps one width per language whatever its value (`FilterSelect`
 * `sizeLabels`); "Set by the view" is cut to that width, in full in its title.
 */
export function FindingsBaseChips({
  practice,
  practiceCounts,
  practiceFromView,
  onPracticeChange,
  lens,
  lensFromView,
  onLensChange,
  inSheet = false,
}: FindingsBaseChipsProps) {
  const { t } = useTranslation()
  const fromView = t('findings.baseChip.fromView', 'Set by the view')
  const practices = practiceTabs(practiceCounts?.byPractice, practice)
  const chips = (
    <>
      <FilterSelect<PracticeView>
        label={t('findings.baseChip.practice', 'Practice')}
        value={practiceFromView ? '' : practice}
        allLabel={fromView}
        clearable={false}
        foldLabel
        options={practices.map((v) => ({
          value: v,
          label: t(practiceLabelKey(v), PRACTICE_VIEW_TEXT[v].label),
        }))}
        // Sized by every practice, not the ones holding findings now: a
        // practice appearing never widens the chip.
        sizeLabels={(Object.keys(PRACTICE_VIEW_TEXT) as PracticeView[]).map((v) =>
          t(practiceLabelKey(v), PRACTICE_VIEW_TEXT[v].label)
        )}
        onChange={(v) => v && onPracticeChange(v)}
        className={inSheet ? undefined : TOOLBAR_ONLY_WHEN_ROOM}
      />
      <FilterSelect<FindingLens>
        label={t('findings.baseChip.state', 'State')}
        value={lensFromView ? '' : lens}
        allLabel={fromView}
        clearable={false}
        foldLabel
        options={FINDING_LENSES.map((l) => ({
          value: l.value,
          label: t(lensLabelKey(l.value), l.label),
        }))}
        onChange={(v) => v && onLensChange(v)}
        className={inSheet ? undefined : TOOLBAR_ONLY_WHEN_ROOM}
      />
    </>
  )
  return inSheet ? (
    <div data-testid="findings-base-chips-sheet" className="flex flex-wrap gap-2 pb-3 lg:hidden">
      {chips}
    </div>
  ) : (
    chips
  )
}
