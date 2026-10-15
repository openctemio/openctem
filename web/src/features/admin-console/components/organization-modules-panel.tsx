'use client'

import { useId, useState } from 'react'
import { RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import type { ModuleEntitlement } from '@/lib/api/generated'
import { deleteModuleDeny, putModuleDeny, useTenantModuleEntitlements } from '../api/use-limits'
import { AdminConfirmDialog, type AdminConfirmProof } from './admin-confirm-dialog'

/** How a module state reads in the table: [translation key, English]. */
export const STATE_LABEL: Record<string, [string, string]> = {
  core: ['admin.modules.state.core', 'Always on'],
  available: ['admin.modules.state.available', 'Available'],
  denied: ['admin.modules.state.denied', 'Denied'],
  // Denied recently: read-only (view and export) until read_only_until.
  grace: ['admin.modules.state.grace', 'Read-only'],
}

type Action = { module: ModuleEntitlement; kind: 'deny' | 'allow' }

export interface OrganizationModulesPanelProps {
  tenantId: string
  /** Operations admins and up deny modules or allow them again. */
  canManage: boolean
}

/**
 * Console > Organizations > an organization > Modules: every module is
 * available unless denied. Denying a module and allowing it again each need a
 * reason (admin audit log) and a fresh authenticator code. A denied module is
 * read-only for 30 days, then off; its data is kept. A deny set by the
 * service operator is read-only here.
 */
export function OrganizationModulesPanel({ tenantId, canManage }: OrganizationModulesPanelProps) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useTenantModuleEntitlements(tenantId)
  const [action, setAction] = useState<Action | null>(null)

  if (error) {
    return (
      <ErrorState
        title={t('admin.modules.errorTitle', 'the modules')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) {
    return <Skeleton className="h-80 w-full" />
  }

  const rows = (data.modules ?? []).filter((m) => !m.core)
  const stateLabel = (state?: string) => {
    const l = STATE_LABEL[state ?? '']
    return l ? t(l[0], l[1]) : state
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('admin.modules.title', 'Modules')}</CardTitle>
        <CardDescription>
          {t(
            'admin.modules.description',
            'Every module is available to this organization unless denied here; it then switches on or off what is available. Core modules are always on and not listed.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.modules.col.module', 'Module')}</TableHead>
                <TableHead>{t('admin.modules.col.state', 'State')}</TableHead>
                <TableHead>{t('admin.modules.col.reason', 'Reason')}</TableHead>
                {canManage && (
                  <TableHead className="text-end">
                    {t('admin.modules.col.change', 'Change')}
                  </TableHead>
                )}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((m) => (
                <TableRow key={m.module}>
                  <TableCell className="font-medium">{m.name}</TableCell>
                  <TableCell>
                    <Badge variant={m.entitled ? 'secondary' : 'outline'}>
                      {stateLabel(m.state)}
                    </Badge>
                    {m.expires_at && m.state === 'denied' && (
                      <span className="text-muted-foreground ms-2 text-xs">
                        {t('admin.modules.until', 'until {date}', {
                          date: new Date(m.expires_at).toLocaleDateString(),
                        })}
                      </span>
                    )}
                    {m.read_only_until && (
                      <span className="text-muted-foreground ms-2 text-xs">
                        {t('admin.modules.until', 'until {date}', {
                          date: new Date(m.read_only_until).toLocaleDateString(),
                        })}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground max-w-xs truncate text-sm">
                    {m.origin === 'control_plane'
                      ? t('limits.console.origin.setByService', 'Set by the service operator')
                      : m.reason}
                  </TableCell>
                  {canManage && (
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        {m.origin === 'control_plane' ? null : m.state === 'denied' ||
                          m.state === 'grace' ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setAction({ module: m, kind: 'allow' })}
                            aria-label={t('admin.modules.allowAria', 'Allow {name} again', {
                              name: m.name ?? '',
                            })}
                          >
                            <RotateCcw className="size-4" />
                          </Button>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setAction({ module: m, kind: 'deny' })}
                          >
                            {t('admin.modules.deny', 'Deny')}
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
            {t('admin.modules.needsOps', 'Denying a module needs an operations admin.')}
          </p>
        )}
      </CardContent>
      {action && (
        <ModuleActionDialog
          key={`${action.module.module}-${action.kind}`}
          tenantId={tenantId}
          action={action}
          onClose={() => setAction(null)}
          onSaved={(next) => void mutate(next, { revalidate: false })}
        />
      )}
    </Card>
  )
}

function todayISO(): string {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

/**
 * Deny one module, or allow it again, through the console's shared
 * confirmation: what happens, a reason and a fresh authenticator code.
 */
function ModuleActionDialog({
  tenantId,
  action,
  onClose,
  onSaved,
}: {
  tenantId: string
  action: Action
  onClose: () => void
  onSaved: (next: Awaited<ReturnType<typeof putModuleDeny>>) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const [expires, setExpires] = useState('')
  const [today] = useState(todayISO)
  const { module, kind } = action
  const name = module.name ?? module.module ?? ''
  const expiryBad = !!expires && expires < today

  const confirm = async (proof: AdminConfirmProof) => {
    const moduleId = module.module ?? ''
    if (kind === 'allow') {
      onSaved(
        await deleteModuleDeny(tenantId, moduleId, {
          reason: proof.reason,
          totp_code: proof.totp_code ?? '',
        })
      )
      toast.success(t('admin.modules.allowed', '{name} is available again', { name }))
      return
    }
    onSaved(
      await putModuleDeny(tenantId, moduleId, {
        reason: proof.reason,
        totp_code: proof.totp_code ?? '',
        expires_at: expires ? new Date(`${expires}T23:59:59`).toISOString() : undefined,
      })
    )
    toast.success(t('admin.modules.denied', '{name} denied', { name }))
  }

  return (
    <AdminConfirmDialog
      open
      onOpenChange={(open) => !open && onClose()}
      title={
        kind === 'deny'
          ? t('admin.modules.denyTitle', 'Deny {name}', { name })
          : t('admin.modules.allowTitle', 'Allow {name} again?', { name })
      }
      description={
        <>
          <p>
            {kind === 'deny'
              ? t(
                  'admin.modules.denyWhat',
                  'The organization can only read this module for 30 days (view and export; no changes, its jobs stop), then loses it. Its data is kept.'
                )
              : t(
                  'admin.modules.allowWhat',
                  'The deny ends and the organization can switch the module on again.'
                )}
          </p>
          <p>
            {t(
              'admin.modules.auditNote',
              'Takes effect at once and is recorded in the admin audit log.'
            )}
          </p>
        </>
      }
      confirmLabel={
        kind === 'deny' ? t('admin.modules.deny', 'Deny') : t('admin.modules.allow', 'Allow again')
      }
      destructive={kind === 'deny'}
      requireCode
      canSubmit={!expiryBad}
      onConfirm={confirm}
    >
      {kind === 'deny' && (
        <div className="space-y-1.5">
          <Label htmlFor={`${id}-e`}>{t('admin.modules.expires', 'Expires (optional)')}</Label>
          <Input
            id={`${id}-e`}
            type="date"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
            aria-invalid={expiryBad}
          />
          {expiryBad && (
            <p className="text-sm text-destructive">
              {t('admin.modules.expiryPast', 'Pick a date in the future.')}
            </p>
          )}
        </div>
      )}
    </AdminConfirmDialog>
  )
}
