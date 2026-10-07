'use client'

/**
 * Settings › Policies › Scope policy (RFC-054 §6.3): the organization's scope
 * knobs and the values in effect. Reading needs scope:read; saving needs
 * scope:approve and step-up (enforced by the API).
 */

import { AlertCircle } from 'lucide-react'
import Link from 'next/link'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { PageHeader } from '@/features/shared'
import { useScopeSettingsApi } from '@/features/scope'
import { ScopeSettingsForm } from '@/features/scope/components/scope-settings-form'

export default function ScopeSettingsPage() {
  const { data, error, isLoading, mutate } = useScopeSettingsApi()

  return (
    <Main>
      <PageHeader
        title="Scope policy"
        description="Who may widen what your organization probes, how many must approve, and how one-off entries and discovered names behave."
      >
        <Button asChild variant="outline" size="sm">
          <Link href="/scope">Scope entries</Link>
        </Button>
      </PageHeader>
      <div className="mt-5">
        {error ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>The scope policy could not be loaded</AlertTitle>
            <AlertDescription>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full rounded-xl" />
        ) : (
          <ScopeSettingsForm settings={data} />
        )}
      </div>
    </Main>
  )
}
