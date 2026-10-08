'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { ShieldCheck } from 'lucide-react'
import { EmptyState, ErrorState } from '@/features/shared'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import { decideSSOChange, useSSOChanges, type SSOChange } from '../api/use-sso-changes'

const kindLabel: Record<SSOChange['kind'], string> = {
  saml_config: 'SAML configuration',
  idp_create: 'New identity provider',
  idp_update: 'Identity provider change',
  domain_jit: 'New people on a domain',
}

function ChangeCard({ change, onDecided }: { change: SSOChange; onDecided: () => void }) {
  const { currentTenant } = useTenant()
  const [confirm, setConfirm] = useState<'approve' | 'reject' | null>(null)
  const [busy, setBusy] = useState(false)

  const decide = async (decision: 'approve' | 'reject') => {
    if (!currentTenant) return
    setBusy(true)
    try {
      await decideSSOChange(currentTenant.id, change.id, decision)
      toast.success(decision === 'approve' ? 'SSO change applied' : 'SSO change rejected')
      setConfirm(null)
      onDecided()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Failed to decide the SSO change'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{kindLabel[change.kind] ?? change.kind}</CardTitle>
        <CardDescription>
          Proposed by {change.requested_by || 'a platform administrator'} on{' '}
          {new Date(change.created_at).toLocaleString()}. Expires{' '}
          {new Date(change.expires_at).toLocaleString()}.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm">{change.summary}</p>
        {change.certificate_sha256 && (
          <div className="space-y-1">
            <p className="text-muted-foreground text-xs">
              IdP signing certificate SHA-256 (compare with your identity provider)
            </p>
            <code className="bg-muted block rounded px-2 py-1 text-xs break-all">
              {change.certificate_sha256}
            </code>
          </div>
        )}
        <details>
          <summary className="text-muted-foreground cursor-pointer text-xs">
            Proposed configuration
          </summary>
          <pre className="bg-muted mt-2 max-h-64 overflow-auto rounded p-2 text-xs">
            {JSON.stringify(change.payload, null, 2)}
          </pre>
        </details>
        <div className="flex gap-2">
          <Button size="sm" onClick={() => setConfirm('approve')} disabled={busy}>
            Approve
          </Button>
          <Button size="sm" variant="outline" onClick={() => setConfirm('reject')} disabled={busy}>
            Reject
          </Button>
        </div>
      </CardContent>
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={confirm === 'approve' ? 'Apply this SSO change?' : 'Reject this SSO change?'}
        desc={
          confirm === 'approve'
            ? 'It changes who can sign in to this organization. Approve only a change you expected and whose identity provider you recognize.'
            : 'The proposed change is discarded; the current sign-in configuration stays as it is.'
        }
        confirmText={confirm === 'approve' ? 'Approve' : 'Reject'}
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
  const { data, error, isLoading, mutate } = useSSOChanges({ enabled: canDecide })

  if (!canDecide) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="Owners only"
        description="SSO changes proposed by the platform administrator are approved or rejected by an owner of this organization."
      />
    )
  }
  if (isLoading) return <Skeleton className="h-40 w-full" />
  if (error) {
    return <ErrorState title="SSO changes" error={error} onRetry={() => void mutate()} />
  }
  const changes = data?.changes ?? []
  if (changes.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="Nothing to approve"
        description="There are no SSO changes waiting for your approval."
      />
    )
  }
  return (
    <div className="space-y-4">
      {changes.map((c) => (
        <ChangeCard key={c.id} change={c} onDecided={() => void mutate()} />
      ))}
    </div>
  )
}
