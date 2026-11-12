'use client'

import { Tabs, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import type { PracticeCounts } from '../api/use-practice-counts'
import {
  PRACTICE_VIEW_TEXT,
  practiceDescriptionKey,
  practiceLabelKey,
  practiceTabs,
  type PracticeView,
} from '../lib/practice'

interface PracticeSwitchProps {
  value: PracticeView
  counts?: PracticeCounts
  onChange: (view: PracticeView) => void
}

function countOf(view: PracticeView, counts?: PracticeCounts): number | undefined {
  if (!counts) return undefined
  if (view === 'vulnerabilities') return counts.vulnerabilities
  if (view === 'all') return counts.total
  return counts.byPractice[view] ?? 0
}

/**
 * The practice switch at the top of the findings list: Vulnerabilities (the
 * default: every practice except compliance), Compliance, each other practice
 * that holds findings, and All, each with the caller's count under the
 * list's other filters.
 */
export function PracticeSwitch({ value, counts, onChange }: PracticeSwitchProps) {
  const { t } = useTranslation()
  const tabs = practiceTabs(counts?.byPractice, value)
  return (
    <Tabs value={value} onValueChange={(v) => onChange(v as PracticeView)}>
      <TabsList
        aria-label={t('findings.practice.switchLabel', 'Findings by practice')}
        data-testid="findings-practice-switch"
      >
        {tabs.map((view) => {
          const n = countOf(view, counts)
          return (
            <TabsTrigger
              key={view}
              value={view}
              data-testid={`findings-practice-${view}`}
              title={t(practiceDescriptionKey(view), PRACTICE_VIEW_TEXT[view].description)}
            >
              {t(practiceLabelKey(view), PRACTICE_VIEW_TEXT[view].label)}
              <TabsCount value={n} />
            </TabsTrigger>
          )
        })}
      </TabsList>
    </Tabs>
  )
}
