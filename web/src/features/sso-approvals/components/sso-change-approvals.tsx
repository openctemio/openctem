'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { ShieldCheck } from 'lucide-react'
import { EmptyState, ErrorState, PageStack } from '@/features/shared'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import { decideSSOChange, useSSOChanges, type SSOChange } from '../api/use-sso-changes'
import { useTranslation } from '@/context/i18n-provider'

const kindLabel: Record<SSOChange['kind'], { key: string; fallback: string }> = {
  saml_config: { key: 'settings.ssoApprovals.kind.samlConfig', fallback: 'SAML configuration' },
  idp_create: { key: 'settings.ssoApprovals.kind.idpCreate', fallback: 'New identity provider' },
  idp_update: {
    key: 'settings.ssoApprovals.kind.idpUpdate',
    fallback: 'Identity provider change',
  },
  domain_jit: { key: 'settings.ssoApprovals.kind.domainJit', fallback: 'New people on a domain' },
}

function ChangeCard({ change, onDecided }: { change: SSOChange; onDecided: () => void }) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const [confirm, setConfirm] = useState<'approve' | 'reject' | null>(null)
  const [busy, setBusy] = useState(false)

  const decide = async (decision: 'approve' | 'reject') => {
    if (!currentTenant) return
    setBusy(true)
    try {
      await decideSSOChange(currentTenant.id, change.id, decision)
      toast.success(
        decision === 'approve'
          ? t('settings.ssoApprovals.applied', 'SSO change applied')
          : t('settings.ssoApprovals.rejected', 'SSO change rejected')
      )
      setConfirm(null)
      onDecided()
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t('settings.ssoApprovals.decideFailed', 'Failed to decide the SSO change')
        )
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {kindLabel[change.kind]
            ? t(kindLabel[change.kind].key, kindLabel[change.kind].fallback)
            : change.kind}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.ssoApprovals.proposedBy',
            'Proposed by {who} on {created}. Expires {expires}.',
            {
              who:
                change.requested_by ||
                t('settings.ssoApprovals.platformAdmin', 'a platform administrator'),
              created: new Date(change.created_at).toLocaleString(),
              expires: new Date(change.expires_at).toLocaleString(),
            }
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm">{change.summary}</p>
        {change.certificate_sha256 && (
          <div className="space-y-1">
            <p className="text-muted-foreground text-xs">
              {t(
                'settings.ssoApprovals.certificate',
                'IdP signing certificate SHA-256 (compare with your identity provider)'
              )}
            </p>
            <code className="bg-muted block rounded px-2 py-1 text-xs break-all">
              {change.certificate_sha256}
            </code>
          </div>
        )}
        <details>
          <summary className="text-muted-foreground cursor-pointer text-xs">
            {t('settings.ssoApprovals.payload', 'Proposed configuration')}
          </summary>
          <pre className="bg-muted mt-2 max-h-64 overflow-auto rounded p-2 text-xs">
            {JSON.stringify(change.payload, null, 2)}
          </pre>
        </details>
        <div className="flex gap-2">
          <Button size="sm" onClick={() => setConfirm('approve')} disabled={busy}>
            {t('confirm.ssoChange.approve', 'Approve')}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setConfirm('reject')} disabled={busy}>
            {t('confirm.reject', 'Reject')}
          </Button>
        </div>
      </CardContent>
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={
          confirm === 'approve'
            ? t('confirm.ssoChange.approveTitle', 'Apply this SSO change?')
            : t('confirm.ssoChange.rejectTitle', 'Reject this SSO change?')
        }
        desc={
          confirm === 'approve'
            ? t(
                'confirm.ssoChange.approveDesc',
                'It changes who can sign in to this organization. Approve only a change you expected and whose identity provider you recognize.'
              )
            : t(
                'confirm.ssoChange.rejectDesc',
                'The proposed change is discarded; the current sign-in configuration stays as it is.'
              )
        }
        confirmText={
          confirm === 'approve'
            ? t('confirm.ssoChange.approve', 'Approve')
            : t('confirm.reject', 'Reject')
        }
        destructive={confirm === 'reject'}
        isLoading={busy}
        handleConfirm={() => confirm && void decide(confirm)}
      />
    </Card>
  )
}

/**
 * SSO changes a platform administrator proposed for this organization, with
 * approve/reject for the owner. None takes effect until an owner approves it.
 */
export function SSOChangeApprovals({ canDecide }: { canDecide: boolean }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSSOChanges({ enabled: canDecide })

  if (!canDecide) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title={t('settings.ssoApprovals.ownersOnly', 'Owners only')}
        description={t(
          'settings.ssoApprovals.ownersOnlyDescription',
          'SSO changes proposed by the platform administrator are approved or rejected by an owner of this organization.'
        )}
      />
    )
  }
  if (isLoading) return <Skeleton className="h-40 w-full" />
  if (error) {
    return (
      <ErrorState
        title={t('settings.ssoApprovals.errorTitle', 'SSO changes')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  const changes = data?.changes ?? []
  if (changes.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title={t('settings.ssoApprovals.emptyTitle', 'Nothing to approve')}
        description={t(
          'settings.ssoApprovals.emptyDescription',
          'There are no SSO changes waiting for your approval.'
        )}
      />
    )
  }
  return (
    <PageStack>
      {changes.map((c) => (
        <ChangeCard key={c.id} change={c} onDecided={() => void mutate()} />
      ))}
    </PageStack>
  )
}
