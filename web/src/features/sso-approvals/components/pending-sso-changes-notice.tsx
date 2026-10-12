'use client'

import { Clock } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { usePendingSSOChanges } from '@/features/saml/api/use-saml-config'

/**
 * Admin console: SSO changes submitted for this organization that wait for an
 * owner's approval (RFC-022). Nothing is shown when none is pending.
 */
export function PendingSSOChangesNotice({ tenantId }: { tenantId: string }) {
  const { data } = usePendingSSOChanges(tenantId)
  const changes = data?.changes ?? []
  if (changes.length === 0) return null
  return (
    <Alert>
      <Clock className="h-4 w-4" />
      <AlertTitle>Waiting for an owner&apos;s approval</AlertTitle>
      <AlertDescription>
        <p>
          These changes do not take effect until an owner of the organization approves them under
          Settings › SSO approvals.
        </p>
        <ul className="mt-2 list-disc space-y-1 pl-4">
          {changes.map((c) => (
            <li key={c.id}>
              {c.summary} (expires {new Date(c.expires_at).toLocaleDateString()})
            </li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  )
}
