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
import { isPlanName, PLAN_LABEL } from '@/features/plans/lib/plan-keys'
import type { ModuleEntitlement } from '@/lib/api/generated'
import { deleteModuleGrant, putModuleGrant, useTenantModuleEntitlements } from '../api/use-plans'
import { AdminConfirmDialog, type AdminConfirmProof } from './admin-confirm-dialog'

/** How an entitlement source reads in the table: [translation key, English]. */
export const SOURCE_LABEL: Record<string, [string, string]> = {
  core: ['admin.modules.source.core', 'Always on'],
  plan: ['admin.modules.source.plan', 'In the plan'],
  grant: ['admin.modules.source.grant', 'Granted'],
  deny: ['admin.modules.source.deny', 'Denied'],
  none: ['admin.modules.source.none', 'Not in the plan'],
  // Lost recently: read-only (view and export) until read_only_until.
  grace: ['admin.modules.source.grace', 'Read-only'],
}

type Action = { module: ModuleEntitlement; kind: 'grant' | 'deny' | 'remove' }

export interface OrganizationModulesPanelProps {
  tenantId: string
  /** Operations admins and up grant or deny modules. */
  canManage: boolean
}

/**
 * Console > Organizations > an organization > Modules: what the organization
 * may use. The plan decides; a grant adds a module (a trial with an expiry, an
 * add-on) and a deny removes one. Granting, denying and removing a grant each
 * need a reason (admin audit log) and a fresh authenticator code. The
 * organization then switches on or off what it is entitled to.
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

  const plan = data.plan ?? ''
  const rows = (data.modules ?? []).filter((m) => !m.core)
  const sourceLabel = (source?: string) => {
    const l = SOURCE_LABEL[source ?? '']
    return l ? t(l[0], l[1]) : source
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('admin.modules.title', 'Modules')}</CardTitle>
        <CardDescription>
          {t(
            'admin.modules.description',
            'What this organization may use under its plan ({plan}). Grant a module for a trial or an add-on, or deny one; the organization switches on or off what it is entitled to. Core modules are always on and not listed.',
            { plan: isPlanName(plan) ? PLAN_LABEL[plan] : plan }
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.modules.col.module', 'Module')}</TableHead>
                <TableHead>{t('admin.modules.col.entitlement', 'Entitlement')}</TableHead>
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
                      {sourceLabel(m.source)}
                    </Badge>
                    {m.grant_expires_at && m.source !== 'grace' && (
                      <span className="text-muted-foreground ms-2 text-xs">
                        {t('admin.modules.until', 'until {date}', {
                          date: new Date(m.grant_expires_at).toLocaleDateString(),
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
                    {m.grant_reason}
                  </TableCell>
                  {canManage && (
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        {m.source === 'grant' || m.source === 'deny' ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setAction({ module: m, kind: 'remove' })}
                            aria-label={t(
                              'admin.modules.removeAria',
                              'Let the plan decide {name}',
                              {
                                name: m.name ?? '',
                              }
                            )}
                          >
                            <RotateCcw className="size-4" />
                          </Button>
                        ) : m.entitled ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setAction({ module: m, kind: 'deny' })}
                          >
                            {t('admin.modules.deny', 'Deny')}
                          </Button>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setAction({ module: m, kind: 'grant' })}
                          >
                            {t('admin.modules.grant', 'Grant')}
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
            {t('admin.modules.needsOps', 'Granting or denying a module needs an operations admin.')}
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
 * Grant, deny or remove one module through the console's shared
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
  onSaved: (next: Awaited<ReturnType<typeof putModuleGrant>>) => void
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
    if (kind === 'remove') {
      onSaved(
        await deleteModuleGrant(tenantId, moduleId, {
          reason: proof.reason,
          totp_code: proof.totp_code ?? '',
        })
      )
      toast.success(t('admin.modules.removed', '{name}: the plan decides again', { name }))
      return
    }
    onSaved(
      await putModuleGrant(tenantId, moduleId, {
        kind,
        reason: proof.reason,
        totp_code: proof.totp_code ?? '',
        expires_at: expires ? new Date(`${expires}T23:59:59`).toISOString() : undefined,
      })
    )
    toast.success(
      kind === 'grant'
        ? t('admin.modules.granted', '{name} granted', { name })
        : t('admin.modules.denied', '{name} denied', { name })
    )
  }

  const title =
    kind === 'grant'
      ? t('admin.modules.grantTitle', 'Grant {name}', { name })
      : kind === 'deny'
        ? t('admin.modules.denyTitle', 'Deny {name}', { name })
        : t('admin.modules.removeTitle', 'Let the plan decide {name}?', { name })
  const description =
    kind === 'grant'
      ? t(
          'admin.modules.grantWhat',
          'The organization may use this module although its plan does not include it, for example for a trial. Set an expiry for a trial.'
        )
      : kind === 'deny'
        ? t(
            'admin.modules.denyWhat',
            'The organization can only read this module for 30 days (view and export; no changes, its jobs stop), then loses it, although its plan includes it. Its data is kept.'
          )
        : module.source === 'grant'
          ? t(
              'admin.modules.removeGrantWhat',
              'The grant ends and the plan decides again. If the plan does not include this module, the organization can only read it for 30 days (view and export; no changes, its jobs stop), then loses it. Its data is kept.'
            )
          : t(
              'admin.modules.removeDenyWhat',
              'The deny ends and the plan decides again. If the plan includes this module, the organization can switch it on again.'
            )

  return (
    <AdminConfirmDialog
      open
      onOpenChange={(open) => !open && onClose()}
      title={title}
      description={
        <>
          <p>{description}</p>
          <p>
            {t(
              'admin.modules.auditNote',
              'Takes effect at once and is recorded in the admin audit log.'
            )}
          </p>
        </>
      }
      confirmLabel={
        kind === 'grant'
          ? t('admin.modules.grant', 'Grant')
          : kind === 'deny'
            ? t('admin.modules.deny', 'Deny')
            : t('admin.modules.remove', 'Let the plan decide')
      }
      destructive={kind !== 'grant'}
      requireCode
      canSubmit={!expiryBad}
      onConfirm={confirm}
    >
      {kind !== 'remove' && (
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
