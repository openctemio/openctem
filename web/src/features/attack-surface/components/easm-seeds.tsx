'use client'

/**
 * Boundaries › Seeds (RFC-036 §6.3): what the organization says is its own,
 * from which external-surface discovery expands. Today a seed is a root
 * domain: the Certificate Transparency monitor watches it, and names found
 * under it wait for ownership review unless the domain is verified.
 *
 * The server is the boundary: it normalizes and validates every value
 * (public suffixes and providers' shared domains are refused), takes the
 * tenant from the session, computes verification from the organization's
 * own verified domains, requires the attestation and audits every change.
 */

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { BadgeCheck, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { DataTable, ErrorState, RelativeTime } from '@/features/shared'
import type { EASMSeed } from '@/lib/api/generated'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { createSeed, deleteSeed, updateSeed, useEASMSeeds } from '../hooks/use-easm-seeds'
import { domainFor, useEASMVerifiedDomains } from '../hooks/use-easm-verified-domains'
import { VerifyDomainDialog } from './easm-verify-domain-dialog'

export function EASMSeedsPanel() {
  const { can } = usePermissions()
  const canWrite = can(Permission.ScopeWrite)
  const canDelete = can(Permission.ScopeDelete)
  const { seeds, error, isLoading, mutate, enabled } = useEASMSeeds()
  const { domains, mutate: mutateDomains } = useEASMVerifiedDomains()
  const [verifying, setVerifying] = useState<string | null>(null)

  const [addOpen, setAddOpen] = useState(false)
  const [value, setValue] = useState('')
  const [label, setLabel] = useState('')
  const [attested, setAttested] = useState(false)
  const [saving, setSaving] = useState(false)
  const [removing, setRemoving] = useState<EASMSeed | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)

  const resetForm = () => {
    setValue('')
    setLabel('')
    setAttested(false)
  }

  const add = async () => {
    setSaving(true)
    try {
      const s = await createSeed({
        kind: 'root_domain',
        value: value.trim(),
        label: label.trim() || undefined,
      })
      toast.success(
        s.status === 'pending'
          ? `${s.pattern} requested: it takes effect once another administrator approves it`
          : `${s.pattern} added to scope`
      )
      setAddOpen(false)
      resetForm()
      void mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Could not add the seed'))
    } finally {
      setSaving(false)
    }
  }

  // Stable across renders: it reads only its arguments, the state setter and
  // SWR's bound mutate, so the column definitions can depend on it.
  const toggle = useCallback(
    async (s: EASMSeed, on: boolean) => {
      if (!s.id) return
      setBusyId(s.id)
      try {
        await updateSeed(s.id, { discovery_enabled: on })
        void mutate()
      } catch (e) {
        toast.error(getErrorMessage(e, 'Could not change the seed'))
      } finally {
        setBusyId(null)
      }
    },
    [mutate]
  )

  const remove = async () => {
    if (!removing?.id) return
    setBusyId(removing.id)
    try {
      await deleteSeed(removing.id)
      toast.success(`Seed ${removing.value} removed`)
      setRemoving(null)
      void mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Could not remove the seed'))
    } finally {
      setBusyId(null)
    }
  }

  const columns = useMemo<ColumnDef<EASMSeed>[]>(
    () => [
      {
        id: 'value',
        header: 'Root domain',
        cell: ({ row }) => (
          <div className="min-w-0">
            <div className="font-medium">{row.original.value}</div>
            {row.original.label && (
              <div className="text-xs text-muted-foreground">{row.original.label}</div>
            )}
          </div>
        ),
      },
      {
        id: 'verification',
        header: 'Ownership',
        cell: ({ row }) =>
          row.original.verification === 'dns_txt' ? (
            <Badge variant="outline" className="gap-1 border-0 bg-success/15 text-success">
              <BadgeCheck className="h-3 w-3" aria-hidden />
              Verified{row.original.verified_domain ? ` (${row.original.verified_domain})` : ''}
            </Badge>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Asserted, not verified</span>
              {canWrite && row.original.value && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7"
                  onClick={() => setVerifying(row.original.value ?? null)}
                >
                  {domainFor(row.original.value, domains) ? 'Check' : 'Verify'}
                </Button>
              )}
            </div>
          ),
      },
      {
        id: 'discovery',
        header: 'Discovery',
        cell: ({ row }) => (
          <Switch
            checked={!!row.original.discovery_enabled}
            disabled={!canWrite || busyId === row.original.id}
            onCheckedChange={(on) => void toggle(row.original, on)}
            aria-label={`Discovery from ${row.original.value}`}
          />
        ),
      },
      {
        id: 'attested',
        header: 'Added',
        cell: ({ row }) =>
          row.original.attested_at ? <RelativeTime date={row.original.attested_at} /> : null,
      },
      {
        id: 'actions',
        header: () => <span className="sr-only">Actions</span>,
        cell: ({ row }) =>
          canDelete ? (
            <Button
              size="icon"
              variant="ghost"
              aria-label={`Remove ${row.original.value}`}
              onClick={() => setRemoving(row.original)}
            >
              <Trash2 className="h-4 w-4" aria-hidden />
            </Button>
          ) : null,
      },
    ],
    [canWrite, canDelete, busyId, toggle, domains]
  )

  if (!enabled && !isLoading) {
    return (
      <p className="text-sm text-muted-foreground">
        Seeds are part of the Attack surface module, which is not enabled for this organization.
      </p>
    )
  }
  if (error) {
    return <ErrorState title="seeds" error={error} onRetry={() => void mutate()} />
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Root domains your organization owns. Discovery watches Certificate Transparency for names
        under them; names under a domain you have not verified wait for ownership review, and scans
        skip them until confirmed.
      </p>
      <DataTable
        columns={columns}
        data={seeds}
        getRowId={(r) => r.id ?? r.value ?? ''}
        showSearch={false}
        toolbarEnd={
          canWrite ? (
            <Button size="sm" onClick={() => setAddOpen(true)}>
              <Plus className="me-2 h-4 w-4" aria-hidden />
              Add seed
            </Button>
          ) : undefined
        }
        emptyMessage={isLoading ? 'Loading…' : 'No seeds yet'}
        emptyDescription={isLoading ? undefined : 'Add a root domain to start discovery from it.'}
      />

      <Dialog
        open={addOpen}
        onOpenChange={(open) => {
          setAddOpen(open)
          if (!open) resetForm()
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add a seed</DialogTitle>
            <DialogDescription>
              A root domain your organization owns. Discovery covers it and every name under it.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="seed-value">Root domain</Label>
              <Input
                id="seed-value"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="example.com"
                autoComplete="off"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="seed-label">Label (optional)</Label>
              <Input
                id="seed-label"
                value={label}
                maxLength={200}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="Main brand"
              />
            </div>
            <div className="flex items-start gap-2">
              <Checkbox
                id="seed-attest"
                checked={attested}
                onCheckedChange={(v) => setAttested(v === true)}
              />
              <Label htmlFor="seed-attest" className="text-sm leading-snug font-normal">
                I confirm my organization owns this domain and is authorized to have it discovered
                and checked. This is recorded with my name.
              </Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)} disabled={saving}>
              Cancel
            </Button>
            <Button onClick={() => void add()} disabled={saving || !attested || !value.trim()}>
              Add seed
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <VerifyDomainDialog
        key={verifying ?? 'closed'}
        domain={verifying}
        existing={domainFor(verifying ?? undefined, domains)}
        onOpenChange={(open) => !open && setVerifying(null)}
        onChanged={() => {
          void mutateDomains()
          void mutate()
        }}
      />

      <ConfirmDialog
        open={!!removing}
        onOpenChange={(open) => !open && setRemoving(null)}
        title="Remove seed?"
        desc={
          <>
            Stop discovery from &quot;{removing?.value}&quot;? Assets already found stay in the
            inventory.
          </>
        }
        confirmText="Remove"
        destructive
        isLoading={!!removing && busyId === removing.id}
        handleConfirm={() => void remove()}
      />
    </div>
  )
}
