'use client'

import type { ReactNode } from 'react'
import { AlertCircle } from 'lucide-react'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'

/** A settings page while its settings load: the header, then placeholders. */
export function SettingsLoading({ header }: { header: ReactNode }) {
  return (
    <Main>
      {header}
      <div className="mt-5 space-y-5" aria-busy="true">
        <Skeleton className="h-9 w-96 max-w-full" />
        <Skeleton className="h-64 w-full rounded-xl" />
        <Skeleton className="h-64 w-full rounded-xl" />
      </div>
    </Main>
  )
}

/** A settings page whose settings could not be read: never shown as defaults. */
export function SettingsLoadError({
  header,
  message,
  onRetry,
}: {
  header: ReactNode
  message?: string
  onRetry: () => void
}) {
  const { t } = useTranslation()
  return (
    <Main>
      {header}
      <Alert variant="destructive" className="mt-5">
        <AlertCircle className="h-4 w-4" aria-hidden />
        <AlertTitle>{t('org.settings.loadFailed', 'The settings could not be loaded')}</AlertTitle>
        <AlertDescription>
          {message && <p>{message}</p>}
          <Button variant="outline" size="sm" className="mt-2" onClick={onRetry}>
            {t('common.retry', 'Retry')}
          </Button>
        </AlertDescription>
      </Alert>
    </Main>
  )
}
