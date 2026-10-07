'use client'

/**
 * Scoping › Domain proof (research/53 SC1, SC2): domains the organization has
 * proved it controls with a DNS TXT record. Proof never authorizes a scan by
 * itself; scope entries do. Proof is what platform sensors and intrusive
 * checks require (RFC-054 §8.1), and it marks every entry at or under the
 * domain as verified. Seeds are gone: a root domain to discover from is a
 * scope entry "*.example.com" with discovery on.
 *
 * The server is the boundary: it takes the tenant from the session, refuses
 * public suffixes, rate-limits checks and audits every change. Domains a
 * platform administrator set up for SSO are shown read-only.
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { DataTable, ErrorState } from '@/features/shared'
import type { EASMVerifiedDomain } from '@/lib/api/generated'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { removeVerifiedDomain, useEASMVerifiedDomains } from '../hooks/use-easm-verified-domains'
import { VerifyDomainDialog } from './easm-verify-domain-dialog'

export function EASMDomainProofPanel() {
  const { can } = usePermissions()
  const canWrite = can(Permission.ScopeWrite)
  const canDelete = can(Permission.ScopeDelete)
  const { domains, error, isLoading, mutate } = useEASMVerifiedDomains()
  const [draft, setDraft] = useState('')
  const [verifying, setVerifying] = useState<string | null>(null)
  const [removing, setRemoving] = useState<EASMVerifiedDomain | null>(null)

  const columns = useMemo<ColumnDef<EASMVerifiedDomain>[]>(
    () => [
      { accessorKey: 'domain', header: 'Domain' },
      {
        accessorKey: 'status',
        header: 'Proof',
        cell: ({ row }) => {
          const d = row.original
          const label =
            d.status === 'verified'
              ? 'Verified'
              : d.status === 'failed'
                ? 'Verification lost'
                : 'Waiting for the TXT record'
          return (
            <span className="flex items-center gap-2">
              <Badge variant={d.status === 'verified' ? 'default' : 'secondary'}>{label}</Badge>
              {d.managed && <span className="text-xs text-muted-foreground">SSO, read-only</span>}
            </span>
          )
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => {
          const d = row.original
          if (d.managed) return null
          return (
            <span className="flex justify-end gap-2">
              {canWrite && d.status !== 'verified' && (
                <Button size="sm" variant="outline" onClick={() => setVerifying(d.domain ?? null)}>
                  Check
                </Button>
              )}
              {canDelete && (
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={`Remove ${d.domain ?? 'domain'}`}
                  onClick={() => setRemoving(d)}
                >
                  <Trash2 className="h-4 w-4" aria-hidden />
                </Button>
              )}
            </span>
          )
        },
      },
    ],
    [canWrite, canDelete]
  )

  if (error) {
    return <ErrorState title="domain proof" error={error} onRetry={() => void mutate()} />
  }

  const remove = async () => {
    if (!removing?.id) return
    try {
      await removeVerifiedDomain(removing.id)
      toast.success(`${removing.domain} removed`)
      setRemoving(null)
      void mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Could not remove the domain'))
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Prove you control a domain with a DNS TXT record. Proof does not put anything in scope;
        scope entries do. It marks entries at or under the domain as verified, which platform
        sensors and intrusive checks require.
      </p>
      {canWrite && (
        <form
          className="flex flex-col gap-2 sm:flex-row sm:items-end"
          onSubmit={(e) => {
            e.preventDefault()
            const v = draft.trim().toLowerCase()
            if (v) setVerifying(v)
          }}
        >
          <div className="flex-1 space-y-2">
            <Label htmlFor="proof-domain">Domain</Label>
            <Input
              id="proof-domain"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="example.com"
              autoComplete="off"
            />
          </div>
          <Button type="submit" disabled={!draft.trim()}>
            <Plus className="me-2 h-4 w-4" aria-hidden />
            Prove a domain
          </Button>
        </form>
      )}
      <DataTable
        columns={columns}
        data={domains}
        getRowId={(r) => r.id ?? r.domain ?? ''}
        showSearch={false}
        emptyMessage={isLoading ? 'Loading…' : 'No domain proved yet'}
      />
      <VerifyDomainDialog
        key={verifying ?? 'closed'}
        domain={verifying}
        existing={domains.find((d) => d.domain === verifying)}
        onOpenChange={(open) => !open && setVerifying(null)}
        onChanged={() => {
          setDraft('')
          void mutate()
        }}
      />
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={`Remove ${removing?.domain ?? 'domain'}?`}
        desc="Entries under it stop showing as verified. Platform sensors and intrusive checks then refuse names under it."
        confirmText="Remove"
        destructive
        handleConfirm={() => void remove()}
      />
    </div>
  )
}
