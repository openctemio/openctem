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
import { DataTable, ErrorState } from '@/features/shared'
import type { EASMVerifiedDomain } from '@/lib/api/generated'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { removeVerifiedDomain, useEASMVerifiedDomains } from '../hooks/use-easm-verified-domains'
import { VerifyDomainDialog } from './easm-verify-domain-dialog'
import { useTranslation } from '@/context/i18n-provider'

export function EASMDomainProofPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.ScopeWrite)
  const canDelete = can(Permission.ScopeDelete)
  const { domains, error, isLoading, mutate } = useEASMVerifiedDomains()
  const [draft, setDraft] = useState('')
  // The list's own search (a few rows, filtered in the browser).
  const [query, setQuery] = useState('')
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return q ? domains.filter((d) => (d.domain ?? '').toLowerCase().includes(q)) : domains
  }, [domains, query])
  const [verifying, setVerifying] = useState<string | null>(null)
  const [removing, setRemoving] = useState<EASMVerifiedDomain | null>(null)

  const columns = useMemo<ColumnDef<EASMVerifiedDomain>[]>(
    () => [
      {
        accessorKey: 'domain',
        meta: { kind: 'name', label: t('attackSurface.domainProof.col.domain', 'Domain') },
        header: t('attackSurface.domainProof.col.domain', 'Domain'),
      },
      {
        accessorKey: 'status',
        meta: { label: t('attackSurface.domainProof.col.proof', 'Proof') },
        header: t('attackSurface.domainProof.col.proof', 'Proof'),
        cell: ({ row }) => {
          const d = row.original
          const label =
            d.status === 'verified'
              ? t('attackSurface.domainProof.status.verified', 'Verified')
              : d.status === 'failed'
                ? t('attackSurface.domainProof.status.failed', 'Verification lost')
                : t('attackSurface.domainProof.status.pending', 'Waiting for the TXT record')
          return (
            <span className="flex items-center gap-2">
              <Badge variant={d.status === 'verified' ? 'default' : 'secondary'}>{label}</Badge>
              {d.managed && (
                <span className="text-xs text-muted-foreground">
                  {t('attackSurface.domainProof.managed', 'SSO, read-only')}
                </span>
              )}
            </span>
          )
        },
      },
      {
        id: 'actions',
        // Labelled buttons: as wide as they need (the 48 px actions column cut them).
        meta: { kind: 'decisions' },
        header: '',
        cell: ({ row }) => {
          const d = row.original
          if (d.managed) return null
          return (
            <span className="flex justify-end gap-2">
              {canWrite && d.status !== 'verified' && (
                <Button size="sm" variant="outline" onClick={() => setVerifying(d.domain ?? null)}>
                  {t('attackSurface.domainProof.check', 'Check')}
                </Button>
              )}
              {canDelete && (
                <Button
                  size="icon-sm"
                  variant="ghost"
                  aria-label={t('attackSurface.domainProof.remove', 'Remove {domain}', {
                    domain: d.domain ?? '',
                  })}
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
    [t, canWrite, canDelete]
  )

  if (error) {
    return (
      <ErrorState
        title={t('attackSurface.domainProof.loadTitle', 'domain proof')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  const remove = async () => {
    if (!removing?.id) return
    try {
      await removeVerifiedDomain(removing.id)
      toast.success(
        t('attackSurface.domainProof.removed', '{domain} removed', {
          domain: removing.domain ?? '',
        })
      )
      setRemoving(null)
      void mutate()
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t('attackSurface.domainProof.removeFailed', 'Could not remove the domain')
        )
      )
    }
  }

  return (
    <div className="space-y-4">
      {/* One row (MVP v2: no label or note on a row of its own): the domain
          field, named for assistive technology, and its button. The page
          header says what proof is. */}
      {canWrite && (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            const v = draft.trim().toLowerCase()
            if (v) setVerifying(v)
          }}
        >
          <Input
            id="proof-domain"
            className="min-w-0 flex-1"
            aria-label={t('attackSurface.domainProof.domainLabel', 'Domain to prove')}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="example.com"
            autoComplete="off"
          />
          {/* An icon on a phone, so the field keeps the row's width. */}
          <Button
            iconOnlyBelow="sm"
            type="submit"
            disabled={!draft.trim()}
            title={t('attackSurface.domainProof.prove', 'Prove a domain')}
          >
            <Plus className="h-4 w-4 sm:me-2" aria-hidden />
            <span className="sr-only sm:not-sr-only">
              {t('attackSurface.domainProof.prove', 'Prove a domain')}
            </span>
          </Button>
        </form>
      )}
      <DataTable
        columns={columns}
        data={shown}
        getRowId={(r) => r.id ?? r.domain ?? ''}
        caption={t('attackSurface.domainProof.caption', 'Proved domains')}
        showSearch={false}
        search={{
          value: query,
          onChange: setQuery,
          placeholder: t('attackSurface.domainProof.search', 'Search domains…'),
          label: t('attackSurface.domainProof.searchLabel', 'Search proved domains'),
        }}
        emptyMessage={
          isLoading
            ? t('attackSurface.domainProof.loading', 'Loading…')
            : t('attackSurface.domainProof.empty', 'No domain proved yet')
        }
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
        title={t('confirm.domainProof.removeTitle', 'Remove the domain {domain}?', {
          domain: removing?.domain ?? '',
        })}
        desc={t(
          'confirm.domainProof.removeDesc',
          'Entries under it stop showing as verified. Shared sensors and intrusive checks then refuse names under it.'
        )}
        confirmText={t('confirm.remove', 'Remove')}
        destructive
        handleConfirm={() => void remove()}
      />
    </div>
  )
}
