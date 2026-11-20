'use client'

/**
 * Settings › Scanning › Scope policy (RFC-054 §6.3): the organization's scope
 * knobs and the values in effect. Reading needs scope:read; saving needs
 * scope:approve and step-up (enforced by the API).
 */

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useScopeSettingsApi } from '@/features/scope'
import { ScopeSettingsForm } from '@/features/scope/components/scope-settings-form'
import { Permission, useHasPermission } from '@/lib/permissions'

export default function ScopeSettingsPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useScopeSettingsApi()
  const canEdit = useHasPermission(Permission.ScopeApprove)

  return (
    <SettingsPage
      title={t('scope.settings.title', 'Scope policy')}
      description={t(
        'scope.settings.description',
        'Who may widen what your organization probes, how many must approve, and how one-off entries and discovered names behave.'
      )}
      actions={
        <Button asChild variant="outline">
          <Link href="/scope">{t('scope.settings.entriesLink', 'Scope entries')}</Link>
        </Button>
      }
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
      readOnly={
        canEdit
          ? false
          : t(
              'scope.settings.viewOnly',
              'View only. Only scope approvers can change these settings.'
            )
      }
    >
      {data && <ScopeSettingsForm settings={data} />}
    </SettingsPage>
  )
}
