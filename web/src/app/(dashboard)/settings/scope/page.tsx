'use client'

/**
 * Settings › Scanning › Scope policy (RFC-054 §6.3): the organization's scope
 * knobs and the values in effect. Reading needs scope:read; saving needs
 * scope:approve and step-up (enforced by the API).
 */

import { AlertCircle } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { PageHeader, PageStack } from '@/features/shared'
import { useScopeSettingsApi } from '@/features/scope'
import { useTranslation } from '@/context/i18n-provider'
import { ScopeSettingsForm } from '@/features/scope/components/scope-settings-form'

export default function ScopeSettingsPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useScopeSettingsApi()

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('scope.settings.title', 'Scope policy')}
          description={t(
            'scope.settings.description',
            'Who may widen what your organization probes, how many must approve, and how one-off entries and discovered names behave.'
          )}
        >
          <Button asChild variant="outline" size="sm">
            <Link href="/scope">{t('scope.settings.entriesLink', 'Scope entries')}</Link>
          </Button>
        </PageHeader>
        {error ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>
              {t('scope.settings.loadFailed', 'The scope policy could not be loaded')}
            </AlertTitle>
            <AlertDescription>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                {t('common.retry', 'Retry')}
              </Button>
            </AlertDescription>
          </Alert>
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full rounded-xl" />
        ) : (
          <ScopeSettingsForm settings={data} />
        )}
      </PageStack>
    </Main>
  )
}
