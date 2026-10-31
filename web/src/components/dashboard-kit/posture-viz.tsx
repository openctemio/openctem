'use client'

/**
 * The attack surface posture (api/docs/architecture/easm-posture.md): the
 * grade badge, the score and what each category takes away. One look for
 * the dashboard widget, the Attack surface overview card and the Posture
 * page.
 */

import Link from '@/components/link'
import { Meter, type MeterTone } from '@/features/shared/components/meter'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { PostureCategoryRow, PostureResult } from './types'

export type PostureGradeLetter = 'A' | 'B' | 'C' | 'D' | 'F'

/** Grade to text tone: green for A, through warning, to destructive for D and F. */
const GRADE_TONE: Record<PostureGradeLetter, string> = {
  A: 'text-success border-success/40',
  B: 'text-info border-info/40',
  C: 'text-warning border-warning/40',
  D: 'text-destructive border-destructive/40',
  F: 'text-destructive border-destructive/60',
}

function toneOf(grade: string | undefined): string {
  return GRADE_TONE[(grade ?? '') as PostureGradeLetter] ?? 'text-muted-foreground border-border'
}

export interface PostureGradeProps {
  grade?: string
  score?: number
  size?: 'sm' | 'lg'
  className?: string
}

/** The grade letter in a bordered square, with the score as its accessible name. */
export function PostureGrade({ grade, score, size = 'lg', className }: PostureGradeProps) {
  const { t } = useTranslation()
  const label = grade
    ? t('dashboardKit.posture.gradeLabel', 'Grade {grade}, score {score} of 100', {
        grade,
        score: score ?? 0,
      })
    : t('dashboardKit.posture.noGrade', 'No grade')
  return (
    <span
      role="img"
      aria-label={label}
      data-grade={grade ?? ''}
      className={cn(
        'inline-flex shrink-0 items-center justify-center rounded-md border-2 font-semibold tabular-nums',
        size === 'lg' ? 'size-14 text-3xl' : 'size-8 text-base',
        toneOf(grade),
        className
      )}
    >
      {grade ?? '—'}
    </span>
  )
}

/** The meter tone of a category: how much of its maximum it takes. */
function meterTone(c: PostureCategoryRow): MeterTone {
  if (c.max <= 0 || c.deduction <= 0) return 'default'
  const share = c.deduction / c.max
  if (share >= 0.5) return 'destructive'
  if (share >= 0.2) return 'warning'
  return 'default'
}

/** Formats a deduction ("−4.2", or "0"). */
export function formatDeduction(d: number, locale: string): string {
  if (d <= 0) return '0'
  return `−${d.toLocaleString(locale, { maximumFractionDigits: 1 })}`
}

export interface PostureCategoryListProps {
  categories: PostureCategoryRow[]
  /** Show the "if fixed" score column (the Posture page). */
  showIfFixed?: boolean
  className?: string
}

/** One row per category: name, issues, a meter of the deduction over its maximum. */
export function PostureCategoryList({
  categories,
  showIfFixed,
  className,
}: PostureCategoryListProps) {
  const { t, locale } = useTranslation()
  return (
    <ul className={cn('flex flex-col gap-2', className)}>
      {categories.map((c) => {
        const name = t(`dashboardKit.posture.category.${c.category}`, c.category)
        return (
          <li key={c.category} className="flex flex-col gap-1" data-category={c.category}>
            <div className="flex items-baseline justify-between gap-3 text-sm">
              <span className="truncate">{name}</span>
              <span className="flex shrink-0 items-baseline gap-3 tabular-nums">
                <span className="text-xs text-muted-foreground">
                  {t('dashboardKit.posture.issues', '{count} issues', { count: c.issues })}
                </span>
                {showIfFixed && c.score_if_fixed != null && (
                  <span className="text-xs text-muted-foreground">
                    {t('dashboardKit.posture.ifFixed', 'fixed: {score} ({grade})', {
                      score: c.score_if_fixed,
                      grade: c.grade_if_fixed ?? '',
                    })}
                  </span>
                )}
                <span
                  className={cn(
                    'font-medium',
                    c.deduction > 0 ? 'text-foreground' : 'text-muted-foreground'
                  )}
                >
                  {formatDeduction(c.deduction, locale)}
                </span>
              </span>
            </div>
            <Meter
              value={c.deduction}
              max={c.max}
              tone={meterTone(c)}
              label={t(
                'dashboardKit.posture.meterLabel',
                '{name} takes {value} of at most {max} points',
                {
                  name,
                  value: formatDeduction(c.deduction, locale),
                  max: c.max,
                }
              )}
            />
          </li>
        )
      })}
    </ul>
  )
}

export interface PostureHeadlineProps {
  grade?: string
  score: number
  /** A muted line under the score (surface size, change since last time). */
  caption?: React.ReactNode
}

/** The grade badge with the score out of 100: the one headline of a posture. */
export function PostureHeadline({ grade, score, caption }: PostureHeadlineProps) {
  return (
    <div className="flex items-center gap-3">
      <PostureGrade grade={grade} score={score} />
      <div className="flex min-w-0 flex-col">
        <span className="text-2xl font-semibold tabular-nums" data-testid="posture-score">
          {score}
          <span className="text-sm font-normal text-muted-foreground">/100</span>
        </span>
        {caption && <span className="text-xs text-muted-foreground">{caption}</span>}
      </div>
    </div>
  )
}

/** The dashboard widget: grade, score, next grade and the category deductions. */
export function PostureViz({ result, href }: { result: PostureResult; href?: string | null }) {
  const { t } = useTranslation()
  const next = result.next_grade
    ? result.fix_steps > 0
      ? t('dashboardKit.posture.nextWithSteps', 'Fix {count} items to reach {grade} ({floor})', {
          count: result.fix_steps,
          grade: result.next_grade,
          floor: result.next_floor ?? 0,
        })
      : t('dashboardKit.posture.next', 'Next grade {grade} at {floor}', {
          grade: result.next_grade,
          floor: result.next_floor ?? 0,
        })
    : t('dashboardKit.posture.top', 'Top grade')
  return (
    <div className="flex flex-col gap-3">
      <PostureHeadline
        grade={result.grade}
        score={result.score}
        caption={t('dashboardKit.posture.assets', '{count} surface assets', {
          count: result.assets,
        })}
      />
      {href ? (
        <Link href={href} className="text-sm text-primary hover:underline">
          {next}
        </Link>
      ) : (
        <span className="text-sm">{next}</span>
      )}
      <PostureCategoryList categories={result.categories} />
    </div>
  )
}
