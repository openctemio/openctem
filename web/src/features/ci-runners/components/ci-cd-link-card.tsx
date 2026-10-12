'use client'

/**
 * A link to the CI/CD integration page, with the number of active pipelines.
 * Shown where daemons are listed, so CI pipelines are one click away without
 * being mixed into the sensor list.
 */

import Link from '@/components/link'
import { ArrowRight, Workflow } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

export function CICDLinkCard({ count, className }: { count?: number; className?: string }) {
  const { t } = useTranslation()
  return (
    <Link
      href="/ci-cd"
      className={cn(
        'flex items-center gap-3 rounded-lg border bg-card px-4 py-3 text-sm transition-colors hover:bg-accent',
        className
      )}
    >
      <Workflow className="h-4 w-4 shrink-0 text-muted-foreground" />
      <span className="min-w-0 flex-1">
        <span className="font-medium">
          {count === undefined
            ? t('scans.ci.card.title', 'CI/CD pipelines')
            : t('scans.ci.card.titleCount', 'CI/CD pipelines ({count})', { count })}
        </span>
        <span className="ms-2 text-muted-foreground">
          {t(
            'scans.ci.card.description',
            'Repositories scanned from your CI pipelines, their runs and coverage'
          )}
        </span>
      </span>
      <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground" />
    </Link>
  )
}
