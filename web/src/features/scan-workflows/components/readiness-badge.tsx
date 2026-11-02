'use client'

/**
 * The readiness of a workflow in a list: a badge that says whether it can
 * run for the organization now and, on click, which steps keep it from
 * running, why, and where the fix is done. Optional steps that a run leaves
 * out until a tool for them is installed are listed too, so a ready
 * workflow never hides a skipped step.
 */

import Link from '@/components/link'

import { Badge } from '@/components/ui/badge'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { useTranslation } from '@/context/i18n-provider'
import { safeHref } from '@/lib/safe-href'

import {
  problemSteps,
  readinessLabel,
  skippedSteps,
  stepFix,
  stepFixHref,
  stepReason,
  type StepReadiness,
  type WorkflowReadiness,
} from '../lib/readiness'

export function WorkflowReadinessBadge({
  readiness,
}: {
  readiness: WorkflowReadiness | undefined | null
}) {
  const { t } = useTranslation()
  const problems = problemSteps(readiness)
  const skipped = skippedSteps(readiness)
  const label =
    readinessLabel(readiness, t) ??
    (skipped.length > 0
      ? t('scans.readiness.skippedBadge', undefined, { count: skipped.length })
      : undefined)
  if (!label) return null
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="shrink-0 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={`${label}: ${t('scans.readiness.details')}`}
          onClick={(e) => e.stopPropagation()}
        >
          <Badge variant="outline" className="cursor-pointer text-xs">
            {label}
          </Badge>
        </button>
      </PopoverTrigger>
      <PopoverContent
        className="w-80 space-y-3 text-xs"
        align="start"
        onClick={(e) => e.stopPropagation()}
      >
        {problems.length > 0 && (
          <StepList title={t('scans.readiness.problemsTitle')} steps={problems} />
        )}
        {skipped.length > 0 && (
          <StepList title={t('scans.readiness.skippedTitle')} steps={skipped} />
        )}
      </PopoverContent>
    </Popover>
  )
}

function StepList({ title, steps }: { title: string; steps: StepReadiness[] }) {
  const { t } = useTranslation()
  return (
    <section className="space-y-1.5">
      <p className="font-medium">{title}</p>
      <ul className="space-y-1.5">
        {steps.map((step) => {
          const fix = stepFix(step, t)
          const href = stepFixHref(step)
          return (
            <li key={step.step_key} data-testid={`readiness-step-${step.step_key}`}>
              <p className="font-medium text-foreground">{step.name}</p>
              <p className="text-muted-foreground">{stepReason(step, t)}</p>
              {fix &&
                (href ? (
                  <Link href={safeHref(href) ?? '#'} className="underline">
                    {fix}
                  </Link>
                ) : (
                  <p>{fix}</p>
                ))}
            </li>
          )
        })}
      </ul>
    </section>
  )
}
