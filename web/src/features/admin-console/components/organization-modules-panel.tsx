'use client'

import { useId, useState } from 'react'
import { Loader2, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { ErrorState } from '@/features/shared'
import { isPlanName, PLAN_LABEL } from '@/features/plans/lib/plan-keys'
import type { ModuleEntitlement } from '@/lib/api/generated'
import { deleteModuleGrant, putModuleGrant, useTenantModuleEntitlements } from '../api/use-plans'

const MAX_REASON = 500

/** How an entitlement source reads in the table. */
export const SOURCE_LABEL: Record<string, string> = {
  core: 'Always on',
  plan: 'In the plan',
  grant: 'Granted',
  deny: 'Denied',
  none: 'Not in the plan',
  // Lost recently: read-only (view and export) until read_only_until.
  grace: 'Read-only',
}

export interface OrganizationModulesPanelProps {
  tenantId: string
  /** Operations admins and up grant or deny modules. */
  canManage: boolean
}

/**
 * Console > Organizations > an organization > Modules: what the organization
 * may use. The plan decides; a grant adds a module (a trial with an expiry, an
 * add-on) and a deny removes one. Both need a reason and are recorded in the
 * admin audit log. The organization then switches on or off what it is
 * entitled to.
 */
export function OrganizationModulesPanel({ tenantId, canManage }: OrganizationModulesPanelProps) {
  const { data, error, isLoading, mutate } = useTenantModuleEntitlements(tenantId)
  const [editing, setEditing] = useState<{
    module: ModuleEntitlement
    kind: 'grant' | 'deny'
  } | null>(null)

  if (error) {
    return <ErrorState title="the modules" error={error} onRetry={() => void mutate()} />
  }
  if (isLoading || !data) {
    return <Skeleton className="h-80 w-full" />
  }

  const remove = async (m: ModuleEntitlement) => {
    try {
      await mutate(await deleteModuleGrant(tenantId, m.module ?? ''), { revalidate: false })
      toast.success(`${m.name}: the plan decides again`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not remove the grant')
    }
  }

  const plan = data.plan ?? ''
  const rows = (data.modules ?? []).filter((m) => !m.core)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Modules</CardTitle>
        <CardDescription>
          What this organization may use under its plan (
          {isPlanName(plan) ? PLAN_LABEL[plan] : plan}
          ). Grant a module for a trial or an add-on, or deny one; the organization switches on or
          off what it is entitled to. Core modules are always on and not listed.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Module</TableHead>
                <TableHead>Entitlement</TableHead>
                <TableHead>Reason</TableHead>
                {canManage && <TableHead className="text-end">Change</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((m) => (
                <TableRow key={m.module}>
                  <TableCell className="font-medium">{m.name}</TableCell>
                  <TableCell>
                    <Badge variant={m.entitled ? 'secondary' : 'outline'}>
                      {SOURCE_LABEL[m.source ?? ''] ?? m.source}
                    </Badge>
                    {m.grant_expires_at && m.source !== 'grace' && (
                      <span className="text-muted-foreground ms-2 text-xs">
                        until {new Date(m.grant_expires_at).toLocaleDateString()}
                      </span>
                    )}
                    {m.read_only_until && (
                      <span className="text-muted-foreground ms-2 text-xs">
                        until {new Date(m.read_only_until).toLocaleDateString()}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground max-w-xs truncate text-sm">
                    {m.grant_reason}
                  </TableCell>
                  {canManage && (
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        {m.source === 'grant' || m.source === 'deny' ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => void remove(m)}
                            aria-label={`Let the plan decide ${m.name}`}
                          >
                            <RotateCcw className="size-4" />
                          </Button>
                        ) : m.entitled ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setEditing({ module: m, kind: 'deny' })}
                          >
                            Deny
                          </Button>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setEditing({ module: m, kind: 'grant' })}
                          >
                            Grant
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {!canManage && (
          <p className="mt-3 text-sm text-muted-foreground">
            Granting or denying a module needs an operations admin.
          </p>
        )}
      </CardContent>
      {editing && (
        <GrantDialog
          key={`${editing.module.module}-${editing.kind}`}
          tenantId={tenantId}
          module={editing.module}
          kind={editing.kind}
          onClose={() => setEditing(null)}
          onSaved={(next) => {
            void mutate(next, { revalidate: false })
            setEditing(null)
          }}
        />
      )}
    </Card>
  )
}

function GrantDialog({
  tenantId,
  module,
  kind,
  onClose,
  onSaved,
}: {
  tenantId: string
  module: ModuleEntitlement
  kind: 'grant' | 'deny'
  onClose: () => void
  onSaved: (next: Awaited<ReturnType<typeof putModuleGrant>>) => void
}) {
  const id = useId()
  const [reason, setReason] = useState('')
  const [expires, setExpires] = useState('')
  const [busy, setBusy] = useState(false)
  const [today] = useState(() => {
    const d = new Date()
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
  })
  const expiryBad = !!expires && expires < today
  const reasonBad = reason.trim() === '' || reason.trim().length > MAX_REASON

  const save = async () => {
    setBusy(true)
    try {
      onSaved(
        await putModuleGrant(tenantId, module.module ?? '', {
          kind,
          reason: reason.trim(),
          expires_at: expires ? new Date(`${expires}T23:59:59`).toISOString() : undefined,
        })
      )
      toast.success(kind === 'grant' ? `${module.name} granted` : `${module.name} denied`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not change the module')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {kind === 'grant' ? 'Grant' : 'Deny'} {module.name}
          </DialogTitle>
          <DialogDescription>
            {kind === 'grant'
              ? 'The organization may use this module although its plan does not include it, for example for a trial. Set an expiry for a trial.'
              : 'The organization may no longer use this module although its plan includes it. Its data is kept.'}{' '}
            Takes effect at once and is recorded in the admin audit log.
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={`${id}-r`}>Reason</Label>
            <Textarea
              id={`${id}-r`}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={MAX_REASON}
              rows={2}
              aria-invalid={reasonBad && reason !== ''}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-e`}>Expires (optional)</Label>
            <Input
              id={`${id}-e`}
              type="date"
              value={expires}
              onChange={(e) => setExpires(e.target.value)}
              aria-invalid={expiryBad}
            />
            {expiryBad && <p className="text-sm text-destructive">Pick a date in the future.</p>}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void save()} disabled={reasonBad || expiryBad || busy}>
            {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
            {kind === 'grant' ? 'Grant' : 'Deny'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
