'use client'

import { ReportProblem } from '@/features/shared/components/report-problem'
import { useEffect } from 'react'
import { AlertCircle, TrendingUp } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { reportRouteError } from '@/lib/error-reporting'
import { classifyError } from '@/lib/client-errors'
import { useTranslation } from '@/context/i18n-provider'

interface ErrorProps {
  error: Error & { digest?: string }
  reset: () => void
}

export default function PrioritizationError({ error, reset }: ErrorProps) {
  const { t } = useTranslation()
  // A request that failed is shown by the page itself (with its own Retry), so
  // this boundary only sees a render error or a code chunk that did not load
  // (a new version was deployed under an open tab): say which, not "failed to load data".
  const staleCode = classifyError(error, 'render') === 'chunk_load'
  useEffect(() => {
    reportRouteError(error, '/prioritization', { section: 'prioritization' })
  }, [error])

  return (
    <div className="flex min-h-[50vh] items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
            <AlertCircle className="h-6 w-6 text-destructive" />
          </div>
          <CardTitle className="flex items-center justify-center gap-2">
            <TrendingUp className="h-5 w-5" />
            {t('prioritization.error.title', 'Prioritization Error')}
          </CardTitle>
          <CardDescription>
            {staleCode
              ? t(
                  'prioritization.error.staleCode',
                  'This page was updated while it was open. Reload to get the new version.'
                )
              : t(
                  'prioritization.error.render',
                  'This page could not be shown because something in it broke. Your data was not lost. Try again, or report the problem.'
                )}
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center">
          {error.digest && (
            <p className="text-muted-foreground text-sm">
              {t('prioritization.error.id', 'Error ID: {id}', { id: error.digest })}
            </p>
          )}
        </CardContent>
        <CardFooter className="flex flex-wrap justify-center gap-2">
          {staleCode ? (
            <Button onClick={() => window.location.reload()}>
              {t('prioritization.error.reload', 'Reload')}
            </Button>
          ) : (
            <Button onClick={reset}>{t('prioritization.error.retry', 'Retry')}</Button>
          )}
          <Button variant="outline" onClick={() => window.history.back()}>
            {t('prioritization.error.back', 'Go back')}
          </Button>
          <ReportProblem error={error} />
        </CardFooter>
      </Card>
    </div>
  )
}
