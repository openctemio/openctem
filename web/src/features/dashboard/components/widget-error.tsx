'use client'

import { AlertCircle, RotateCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

interface WidgetErrorProps {
  /** Re-fetches the figures (the SWR `mutate` of the failed read). */
  onRetry?: () => void
  className?: string
}

/**
 * The state of a dashboard card whose read failed. A failed read never shows
 * as zeros: a confident 0 next to a real problem is worse than no number.
 */
export function WidgetError({ onRetry, className }: WidgetErrorProps) {
  const { t } = useTranslation()
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-1 min-h-16 flex-col items-center justify-center gap-2 text-center text-xs text-muted-foreground',
        className
      )}
    >
      <span className="flex items-center gap-1.5">
        <AlertCircle className="h-4 w-4 text-destructive" aria-hidden />
        {t('dashboardMetrics.state.loadFailed', "Couldn't load these figures")}
      </span>
      {onRetry && (
        <Button variant="outline" size="sm" className="h-7" onClick={() => onRetry()}>
          <RotateCw className="mr-1.5 h-3 w-3" aria-hidden />
          {t('dashboardMetrics.state.retry', 'Retry')}
        </Button>
      )}
    </div>
  )
}
