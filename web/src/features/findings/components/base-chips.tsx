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
   * Drawn at the top of the phone filter sheet (the phone toolbar has no
   * room for them); shown only under 768px, where the toolbar ones hide.
   */
  inSheet?: boolean
}

/**
 * The two fixed scopes of the findings list, first after the search: Practice
 * (Vulnerabilities by default) and State (Open by default). They are never
 * removed, only changed, and carry no counts (the count shows once, beside the
 * view name). The practice menu lists Vulnerabilities, Compliance, each other
 * practice that holds findings, and All. While a saved view sets a scope
 * itself, the chip reads "Set by the view" until one is picked.
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
        onChange={(v) => v && onPracticeChange(v)}
        className={inSheet ? undefined : 'max-md:hidden'}
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
        className={inSheet ? undefined : 'max-md:hidden'}
      />
    </>
  )
  return inSheet ? (
    <div data-testid="findings-base-chips-sheet" className="flex flex-wrap gap-2 pb-3 md:hidden">
      {chips}
    </div>
  ) : (
    chips
  )
}
