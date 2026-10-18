'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import type { ColumnDef } from '@tanstack/react-table'
import { AlertTriangle, FileText, RefreshCw, Trash2, UserPlus } from 'lucide-react'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { DataTable } from '@/features/shared/components/data-table'
import { DataTableRowActions } from '@/features/shared/components/data-table-row-actions'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useDeleteVerifiedDomain, useVerifyDomain } from '../api/use-verified-domains'
import type { VerifiedDomain } from '../types/verified-domain.types'
import { DomainJITDialog, jitLabel } from './domain-jit-dialog'
import { DnsInstructions } from './dns-instructions'
import { VerifiedDomainStatusBadge } from './verified-domain-status-badge'
import { useTranslation } from '@/context/i18n-provider'

function DomainActions({
  tenantId,
  domain,
  onChanged,
}: {
  tenantId: string
  domain: VerifiedDomain
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const [dnsOpen, setDnsOpen] = useState(false)
  const [jitOpen, setJitOpen] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const { trigger: verify, isMutating: isVerifying } = useVerifyDomain(tenantId)
  const { trigger: remove, isMutating: isDeleting } = useDeleteVerifiedDomain(tenantId)

  const hasInstructions = domain.status !== 'verified' && !!domain.instructions

  const handleVerify = async () => {
    try {
      const updated = await verify(domain.id)
      onChanged()
      if (updated.status === 'verified') {
        toast.success(
          t('admin.verifiedDomainsList.verified', '{domain} verified', { domain: domain.domain })
        )
      } else {
        toast.info(
          t(
            'admin.verifiedDomainsList.stillPendingTheTxtRecord',
            'Still pending — the TXT record for {domain} was not found yet.',
            { domain: domain.domain }
          )
        )
        if (domain.instructions) setDnsOpen(true)
      }
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('admin.verifiedDomainsList.verificationFailed', 'Verification failed'))
      )
    }
  }

  const handleDelete = async () => {
    try {
      await remove(domain.id)
      toast.success(
        t('admin.verifiedDomainsList.removed', '{domain} removed', { domain: domain.domain })
      )
      setConfirmOpen(false)
      onChanged()
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t('admin.verifiedDomainsList.failedToRemoveDomain', 'Failed to remove domain')
        )
      )
    }
  }

  return (
    <>
      <DataTableRowActions
        actions={[
          ...(hasInstructions
            ? [
                {
                  label: t('admin.verifiedDomainsList.showDnsRecord', 'Show DNS record'),
                  icon: FileText,
                  onClick: () => setDnsOpen(true),
                },
              ]
            : []),
          ...(domain.status !== 'verified'
            ? [
                {
                  label: isVerifying
                    ? t('admin.verifiedDomainsList.checking', 'Checking…')
                    : t('admin.verifiedDomainsList.verifyNow', 'Verify now'),
                  icon: RefreshCw,
                  onClick: () => void handleVerify(),
                  disabled: isVerifying,
                },
              ]
            : []),
          ...(domain.status === 'verified'
            ? [
                {
                  label: t('admin.verifiedDomainsList.newPeople', 'New people…'),
                  icon: UserPlus,
                  onClick: () => setJitOpen(true),
                },
              ]
            : []),
          {
            label: t('admin.verifiedDomainsList.remove', 'Remove'),
            icon: Trash2,
            onClick: () => setConfirmOpen(true),
            destructive: true,
            separatorBefore: true,
          },
        ]}
      />

      {domain.instructions && (
        <Dialog open={dnsOpen} onOpenChange={setDnsOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                {t('admin.verifiedDomainsList.dnsRecordFor', 'DNS record for {domain}', {
                  domain: domain.domain,
                })}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'admin.verifiedDomainsList.publishThisTxtRecordThen',
                  'Publish this TXT record, then choose Verify now.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <DnsInstructions instructions={domain.instructions} />
            </DialogBody>
          </DialogContent>
        </Dialog>
      )}

      <DomainJITDialog
        tenantId={tenantId}
        domain={jitOpen ? domain : null}
        onOpenChange={setJitOpen}
        onSaved={onChanged}
      />

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        destructive
        title={t('confirm.verifiedDomain.removeTitle', 'Remove the domain {domain}?', {
          domain: domain.domain,
        })}
        desc={t(
          'confirm.verifiedDomain.removeDesc',
          'It no longer gates SSO auto-join. You can add and verify it again later.'
        )}
        confirmText={t('confirm.remove', 'Remove')}
        isLoading={isDeleting}
        handleConfirm={handleDelete}
      />
    </>
  )
}

function lastActivity(
  domain: VerifiedDomain,
  t: ReturnType<typeof useTranslation>['t']
): { label: string; date: string } {
  if (domain.status === 'verified' && domain.verified_at) {
    return { label: t('admin.verifiedDomainsList.verified', 'Verified'), date: domain.verified_at }
  }
  if (domain.last_checked_at)
    return {
      label: t('admin.verifiedDomainsList.lastChecked', 'Last checked'),
      date: domain.last_checked_at,
    }
  return { label: t('admin.verifiedDomainsList.added', 'Added'), date: domain.created_at }
}

export function VerifiedDomainsList({
  tenantId,
  domains,
  onChanged,
  canManage = true,
}: {
  /** Organization the domains belong to (admin console, RFC-022). */
  tenantId: string
  domains: VerifiedDomain[]
  onChanged: () => void
  /** False for a read-only administrator: actions are hidden. */
  canManage?: boolean
}) {
  const { t } = useTranslation()

  const columns: ColumnDef<VerifiedDomain>[] = [
    {
      accessorKey: 'domain',
      header: t('admin.verifiedDomainsList.domain', 'Domain'),
      cell: ({ row }) => (
        <span className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{row.original.domain}</span>
          {row.original.claim_conflict && (
            <Badge
              variant="destructive"
              title={t(
                'admin.verifiedDomainsList.anotherOrganizationAlsoVerifiedThis',
                'Another organization also verified this domain for SSO before domain claims became exclusive. Both keep working until you remove one of the claims.'
              )}
            >
              <AlertTriangle />
              {t('admin.verifiedDomainsList.claimConflict', 'Claim conflict')}
            </Badge>
          )}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: t('admin.verifiedDomainsList.status', 'Status'),
      cell: ({ row }) => <VerifiedDomainStatusBadge status={row.original.status} />,
    },
    {
      id: 'jit',
      header: t('admin.verifiedDomainsList.newPeople2', 'New people'),
      enableSorting: false,
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground" data-testid="domain-jit">
          {row.original.status === 'verified'
            ? jitLabel(row.original)
            : t('admin.verifiedDomainsList.notUntilVerified', 'Not until verified')}
        </span>
      ),
    },
    {
      id: 'activity',
      header: t('admin.verifiedDomainsList.lastActivity', 'Last activity'),
      accessorFn: (d) => lastActivity(d, t).date,
      cell: ({ row }) => {
        const { label, date } = lastActivity(row.original, t)
        return (
          <span className="text-sm text-muted-foreground">
            {label} <RelativeTime date={date} />
          </span>
        )
      },
    },
  ]
  if (canManage) {
    columns.push({
      id: 'actions',
      enableSorting: false,
      cell: ({ row }) => (
        <DomainActions tenantId={tenantId} domain={row.original} onChanged={onChanged} />
      ),
    })
  }

  return (
    <DataTable
      columns={columns}
      data={domains}
      getRowId={(d) => d.id}
      searchPlaceholder="Search domains..."
      showSelectionCount={false}
    />
  )
}
