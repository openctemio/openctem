'use client'

/**
 * One compact row for a finding-page section whose read failed (server error
 * or network), with a Retry. Without it the section renders as empty ("not in
 * a task", "—") and misreads as "nothing here". A refusal (403, 404) is not
 * a failure and is not shown here: those sections stay hidden, so the page
 * gives no oracle about what exists.
 */

import { AlertCircle, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/** True for a failure worth showing: not a 403/404 refusal. */
export function isLoadFailure(error: unknown): boolean {
  if (!error) return false
  const status = (error as { statusCode?: unknown }).statusCode
  return status !== 403 && status !== 404
}

export function SectionLoadError({
  title,
  onRetry,
  className,
}: {
  /** What failed to load, already translated, e.g. "ticket links". */
  title: string
  onRetry?: () => void
  className?: string
}) {
  const { t } = useTranslation()
  return (
    <div
      role="alert"
      data-testid="section-load-error"
      className={cn(
        'text-muted-foreground flex flex-wrap items-center gap-2 rounded-md border border-dashed p-2 text-xs',
        className
      )}
    >
      <AlertCircle className="text-destructive size-3.5 shrink-0" aria-hidden />
      <span className="min-w-0">
        {t('findings.detail.sectionError', 'Could not load {title}', { title })}
      </span>
      {onRetry && (
        <Button variant="outline" size="sm" className="h-6 px-2 text-xs" onClick={onRetry}>
          <RefreshCw className="me-1 size-3" aria-hidden />
          {t('common.retry', 'Retry')}
        </Button>
      )}
    </div>
  )
}
