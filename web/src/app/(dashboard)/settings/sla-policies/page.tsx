'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { AlertCircle, Plus, Pencil, Trash2, ShieldCheck, Timer } from 'lucide-react'

import { Main } from '@/components/layout'
import { PageHeader, DataTable, DataTableColumnHeader, EmptyState } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Can, Permission } from '@/lib/permissions'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'

import { SlaPolicyDialog } from '@/features/sla/components/sla-policy-dialog'
import { SlaWindows } from '@/features/sla/components/sla-windows'
import {
  useSlaPoliciesApi,
  useDeleteSlaPolicy,
  invalidateSlaPoliciesCache,
  type SlaPolicy,
} from '@/features/sla/api/use-sla-policies-api'

export default function SlaPoliciesPage() {
  const { data, error, isLoading, mutate } = useSlaPoliciesApi()
  const policies = useMemo(() => data?.data ?? [], [data])
  // Only the default policy governs findings (asset overrides have no editor
  // yet), so creating is offered only while there is no default.
  const hasDefault = policies.some((p) => p.is_default && !p.asset_id)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<SlaPolicy | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SlaPolicy | null>(null)

  const { trigger: deletePolicy, isMutating: isDeleting } = useDeleteSlaPolicy()

  const openCreate = () => {
    setEditing(null)
    setDialogOpen(true)
  }
  const openEdit = (policy: SlaPolicy) => {
    setEditing(policy)
    setDialogOpen(true)
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await deletePolicy({ id: deleteTarget.id })
      toast.success(`Policy "${deleteTarget.name}" deleted`)
      await invalidateSlaPoliciesCache()
      setDeleteTarget(null)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to delete SLA policy'))
    }
  }

  const columns = useMemo<ColumnDef<SlaPolicy>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Policy" />,
        cell: ({ row }) => {
          const p = row.original
          return (
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-2">
                <span className="font-medium">{p.name}</span>
                {p.is_default && (
                  <Badge variant="secondary" className="gap-1">
                    <ShieldCheck className="h-3 w-3" />
                    Default
                  </Badge>
                )}
                {p.asset_id && (
                  <Badge variant="outline" className="text-xs">
                    Asset override
                  </Badge>
                )}
                {!p.is_default && !p.asset_id && (
                  <Badge
                    variant="outline"
                    className="text-xs text-muted-foreground"
                    title="Only the default policy applies to findings. Make this the default to use it."
                  >
                    Not applied
                  </Badge>
                )}
              </div>
              {p.description && (
                <span className="text-xs text-muted-foreground line-clamp-1">{p.description}</span>
              )}
            </div>
          )
        },
      },
      {
        id: 'windows',
        header: 'Remediation windows',
        enableSorting: false,
        cell: ({ row }) => <SlaWindows policy={row.original} />,
      },
      {
        accessorKey: 'warning_threshold_pct',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Warning at" />,
        cell: ({ row }) => (
          <span className="tabular-nums">{row.original.warning_threshold_pct}%</span>
        ),
      },
      {
        accessorKey: 'escalation_enabled',
        header: 'Notifications',
        cell: ({ row }) =>
          row.original.escalation_enabled ? (
            <Badge variant="outline">On</Badge>
          ) : (
            <span className="text-muted-foreground text-sm">Off</span>
          ),
      },
      {
        id: 'actions',
        header: () => <span className="sr-only">Actions</span>,
        enableSorting: false,
        cell: ({ row }) => {
          const p = row.original
          return (
            <div className="flex items-center justify-end gap-1">
              <Can permission={Permission.SLAWrite}>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  aria-label={`Edit ${p.name}`}
                  onClick={() => openEdit(p)}
                >
                  <Pencil className="h-4 w-4" />
                </Button>
              </Can>
              {/* The server refuses to delete the default policy. */}
              {!p.is_default && (
                <Can permission={Permission.SLADelete}>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-destructive"
                    aria-label={`Delete ${p.name}`}
                    onClick={() => setDeleteTarget(p)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </Can>
              )}
            </div>
          )
        },
      },
    ],
    []
  )

  return (
    <Main>
      <PageHeader
        title="SLA policies"
        description="Remediation windows per CTEM priority class (P0–P3), with severity windows for findings that have no class yet. The default policy applies to every finding."
      >
        {!isLoading && !error && !hasDefault && (
          <Can permission={Permission.SLAWrite}>
            <Button size="sm" onClick={openCreate}>
              <Plus className="h-4 w-4" />
              New policy
            </Button>
          </Can>
        )}
      </PageHeader>

      <div className="mt-5">
        {error ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Failed to load SLA policies</AlertTitle>
            <AlertDescription>
              <p>{getErrorMessage(error, 'The SLA policies request failed.')}</p>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        ) : isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full max-w-sm" />
            <Skeleton className="h-64 w-full rounded-md" />
          </div>
        ) : policies.length === 0 ? (
          <EmptyState
            icon={Timer}
            title="No SLA policies yet"
            description="Without a policy the platform defaults apply (P0 2 days, P1 5, P2 15, P3 30). Create the default policy to set your own windows."
            action={
              <Can permission={Permission.SLAWrite}>
                <Button size="sm" onClick={openCreate}>
                  <Plus className="h-4 w-4" />
                  New policy
                </Button>
              </Can>
            }
          />
        ) : (
          <DataTable
            columns={columns}
            data={policies}
            searchKey="name"
            searchPlaceholder="Search policies…"
          />
        )}
      </div>

      <SlaPolicyDialog open={dialogOpen} onOpenChange={setDialogOpen} policy={editing} />

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        onOpenChange={(o) => !o && setDeleteTarget(null)}
        title="Delete SLA policy"
        desc={
          <>
            Delete <strong>{deleteTarget?.name}</strong>? It does not apply to any finding (only the
            default policy does). This action cannot be undone.
          </>
        }
        confirmText="Delete"
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDelete}
      />
    </Main>
  )
}
