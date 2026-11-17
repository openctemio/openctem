'use client'

import type { ReactNode } from 'react'
import { AlertCircle } from 'lucide-react'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { describeApiError } from '@/lib/api/error-message'
import { cn } from '@/lib/utils'
import { PageHeader } from './page-header'
import { PageStack } from './page-stack'
import { ReadOnlyNotice } from './read-only-notice'

export interface SettingsPageProps {
  /** The page title: the only h1, repeated in the phone bar once it scrolls away. */
  title: string
  /** One sentence saying what the page is for. */
  description?: ReactNode
  /** Header actions (at most one primary and two outline buttons). */
  actions?: ReactNode
  /**
   * The caller may read but not change these settings: a notice above the
   * sections. `true` uses the standard sentence; a string replaces it. The
   * page still disables its own controls.
   */
  readOnly?: boolean | string
  /** `loading`: header and skeleton rows. `error`: the load failed (never show defaults). */
  state?: 'ready' | 'loading' | 'error'
  /** The load error, shown through the shared mapper. */
  error?: unknown
  onRetry?: () => void
  /** A list page: the content takes the full width instead of the reading column. */
  wide?: boolean
  /** Banners between the header and the sections (they keep the column width). */
  banners?: ReactNode
  /** The sections (`SettingsSection framed`, `DangerZone`) and, last, the `SettingsSaveBar`. */
  children?: ReactNode
  className?: string
}

/**
 * The frame of a settings page (web/docs/ui-style-contract.md, "Settings
 * pages"): the title and description, then one column of sections at a
 * reading width (`--settings-col`), 16px apart, each divided from the next by
 * a hairline. Loading, load-failed and view-only look the same on every page.
 */
export function SettingsPage({
  title,
  description,
  actions,
  readOnly,
  state = 'ready',
  error,
  onRetry,
  wide = false,
  banners,
  children,
  className,
}: SettingsPageProps) {
  const { t } = useTranslation()
  const column = cn('flex min-w-0 flex-col gap-section', !wide && 'max-w-settings')
  const message = state === 'error' && error ? describeApiError(error, t, '').message : ''
  return (
    <Main>
      <PageStack className={className}>
        <PageHeader title={title} description={description}>
          {actions}
        </PageHeader>
        {state === 'loading' && (
          <div
            data-slot="settings-column"
            className={column}
            aria-busy="true"
            aria-label={t('settings.page.loading', 'Loading {page}', { page: title })}
          >
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="flex items-center justify-between gap-8 border-t border-border-subtle py-3.5 first:border-t-0"
              >
                <div className="min-w-0 flex-1 space-y-2">
                  <Skeleton className="h-4 w-48 max-w-full" />
                  <Skeleton className="h-3 w-80 max-w-full" />
                </div>
                <Skeleton className="h-8 w-32" />
              </div>
            ))}
          </div>
        )}
        {state === 'error' && (
          <Alert variant="destructive" className={cn(!wide && 'max-w-settings')}>
            <AlertCircle aria-hidden />
            <AlertTitle>
              {t('settings.page.loadFailed', "Couldn't load {page}", { page: title })}
            </AlertTitle>
            <AlertDescription>
              <p>
                {message ||
                  t(
                    'settings.page.loadFailedHint',
                    'The server did not answer. Nothing was changed.'
                  )}
              </p>
              {onRetry && (
                <Button variant="outline" className="mt-2" onClick={onRetry}>
                  {t('common.retry', 'Retry')}
                </Button>
              )}
            </AlertDescription>
          </Alert>
        )}
        {state === 'ready' && readOnly && (
          <ReadOnlyNotice
            className={cn(!wide && 'max-w-settings')}
            reason={
              typeof readOnly === 'string'
                ? readOnly
                : t(
                    'settings.page.viewOnly',
                    'View only. Only owners and administrators can change these settings.'
                  )
            }
          />
        )}
        {state === 'ready' && banners}
        {state === 'ready' && (
          <div data-slot="settings-column" className={column}>
            {children}
          </div>
        )}
      </PageStack>
    </Main>
  )
}
