'use client'

/**
 * Settings › Support access (api RFC-063): an owner lets one platform support
 * administrator read chosen data, read-only, for a few hours. Owners and
 * admins see every grant and revoke one at once. Every support read is in the
 * audit log; owners are emailed on each grant, revoke, session start and end.
 */

import { useState } from 'react'
import { AlertCircle, Eye, LifeBuoy, Plus, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'

import Link from '@/components/link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { EmptyState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { SupportGrant } from '@/lib/api/generated'

import { revokeSupportGrant, useSupportGrants } from '../api/use-support-access'
import { formatSupportScopes, formatSupportTime } from '../lib/format'
import { GrantSupportDialog } from './grant-support-dialog'

/** The audit log, searched for support events. */
export const SUPPORT_AUDIT_HREF = '/settings/audit-log?q=support.'

type GrantStatus = 'active' | 'revoked' | 'expired' | 'scheduled'

function statusOf(g: SupportGrant): GrantStatus {
  if (g.active) return 'active'
  if (g.revoked_at) return 'revoked'
  if (g.starts_at && new Date(g.starts_at).getTime() > Date.now()) return 'scheduled'
  return 'expired'
}

function StatusBadge({ grant }: { grant: SupportGrant }) {
  const { t } = useTranslation()
  const s = statusOf(grant)
  if (s === 'active') {
    return (
      <Badge variant="outline" className="border-warning/50 text-warning">
        {t('supportAccess.status.active', 'Active')}
      </Badge>
    )
  }
  if (s === 'revoked') {
    return <Badge variant="secondary">{t('supportAccess.status.revoked', 'Revoked')}</Badge>
  }
  if (s === 'scheduled') {
    return <Badge variant="outline">{t('supportAccess.status.scheduled', 'Not started')}</Badge>
  }
  return <Badge variant="secondary">{t('supportAccess.status.expired', 'Expired')}</Badge>
}

export function SupportAccessSettings({
  canRead,
  isOwner,
}: {
  canRead: boolean
  isOwner: boolean
}) {
  const { t, locale } = useTranslation()
  const { grants, error, isLoading, mutate } = useSupportGrants(canRead)
  const [granting, setGranting] = useState(false)
  const [revoking, setRevoking] = useState<SupportGrant | null>(null)
  const [busy, setBusy] = useState(false)

  const active = grants.filter((g) => g.active)

  async function confirmRevoke() {
    if (!revoking?.id) return
    setBusy(true)
    try {
      await revokeSupportGrant(revoking.id)
      toast.success(t('supportAccess.revoke.done', 'Support access revoked'))
      setRevoking(null)
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  if (!canRead) {
    return (
      <Alert>
        <AlertCircle className="size-4" />
        <AlertDescription>
          {t('supportAccess.ownersOnly', 'Only owners and admins can see support access.')}
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheck className="size-4" aria-hidden="true" />
            {t('supportAccess.how.title', 'How support access works')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="list-disc space-y-1 ps-5 text-sm text-muted-foreground">
            <li>
              {t(
                'supportAccess.how.readOnly',
                'Read-only: support can look, never change anything.'
              )}
            </li>
            <li>
              {t(
                'supportAccess.how.timeBoxed',
                'Time-boxed: you choose 1 to 72 hours; access ends on its own.'
              )}
            </li>
            <li>
              {t(
                'supportAccess.how.audited',
                'Audited: every page support opens is written to your audit log, and every member sees a banner while access is on.'
              )}
            </li>
            <li>
              {t(
                'supportAccess.how.revocable',
                'Revocable: owners and admins can end it at once, including a session in progress.'
              )}
            </li>
            <li>
              {t(
                'supportAccess.how.emailed',
                'Owners are emailed when access is granted or revoked and when support starts or ends a session.'
              )}
            </li>
          </ul>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {isOwner && (
              <Button onClick={() => setGranting(true)}>
                <Plus className="size-4" aria-hidden="true" />
                {t('supportAccess.grant.open', 'Grant access')}
              </Button>
            )}
            <Button variant="outline" asChild>
              <Link href={SUPPORT_AUDIT_HREF}>
                {t('supportAccess.auditLink', 'View support activity in the audit log')}
              </Link>
            </Button>
          </div>
          {!isOwner && (
            <p className="mt-3 text-xs text-muted-foreground">
              {t('supportAccess.ownerGrants', 'Only an owner can grant access.')}
            </p>
          )}
        </CardContent>
      </Card>

      {error ? (
        <Alert variant="destructive">
          <AlertCircle className="size-4" />
          <AlertDescription>{getErrorMessage(error)}</AlertDescription>
        </Alert>
      ) : isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t('supportAccess.active.title', 'Active access')}
              </CardTitle>
              <CardDescription>
                {t(
                  'supportAccess.active.description',
                  'Who from platform support can read your data now.'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {active.length === 0 ? (
                <EmptyState
                  icon={LifeBuoy}
                  title={t('supportAccess.active.empty', 'No one from support has access.')}
                />
              ) : (
                <ul className="divide-y">
                  {active.map((g) => (
                    <li
                      key={g.id}
                      data-testid="support-active-grant"
                      className="flex flex-col gap-3 py-3 sm:flex-row sm:items-start sm:justify-between"
                    >
                      <div className="min-w-0 space-y-1">
                        <p className="flex flex-wrap items-center gap-2 font-medium break-words">
                          {g.admin_name || g.admin_email}
                          {g.open_session && (
                            <Badge
                              variant="outline"
                              className="border-destructive/50 text-destructive"
                            >
                              <Eye className="size-3" aria-hidden="true" />
                              {t('supportAccess.active.viewing', 'Viewing now')}
                            </Badge>
                          )}
                        </p>
                        <p className="text-sm break-words text-muted-foreground">
                          {t('supportAccess.active.summary', 'Can read {scopes} until {time}', {
                            scopes: formatSupportScopes(g.scopes, t),
                            time: formatSupportTime(g.expires_at, locale),
                          })}
                          {g.case_ref
                            ? ` · ${t('supportAccess.caseRef', 'case {ref}', { ref: g.case_ref })}`
                            : ''}
                        </p>
                        <p className="text-sm break-words">{g.reason}</p>
                      </div>
                      <Button
                        variant="destructive"
                        size="sm"
                        className="shrink-0 self-start"
                        onClick={() => setRevoking(g)}
                      >
                        {t('supportAccess.revoke.open', 'Revoke')}
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t('supportAccess.history.title', 'History')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {grants.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('supportAccess.history.empty', 'Support access has never been granted.')}
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('supportAccess.history.admin', 'Administrator')}</TableHead>
                        <TableHead>{t('supportAccess.history.status', 'Status')}</TableHead>
                        <TableHead>{t('supportAccess.history.scopes', 'Data')}</TableHead>
                        <TableHead>{t('supportAccess.history.window', 'Until')}</TableHead>
                        <TableHead className="text-end">
                          {t('supportAccess.history.sessions', 'Sessions')}
                        </TableHead>
                        <TableHead>
                          {t('supportAccess.history.lastAccess', 'Last access')}
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {grants.map((g) => (
                        <TableRow key={g.id} data-testid="support-grant-row">
                          <TableCell className="max-w-56">
                            <div className="truncate font-medium">
                              {g.admin_name || g.admin_email}
                            </div>
                            <div className="truncate text-xs text-muted-foreground">
                              {g.case_ref
                                ? t('supportAccess.caseRef', 'case {ref}', { ref: g.case_ref })
                                : g.admin_email}
                            </div>
                          </TableCell>
                          <TableCell>
                            <StatusBadge grant={g} />
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {formatSupportScopes(g.scopes, t)}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {formatSupportTime(g.revoked_at || g.expires_at, locale)}
                          </TableCell>
                          <TableCell className="text-end tabular-nums">
                            {g.session_count ?? 0}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {g.last_access_at
                              ? formatSupportTime(g.last_access_at, locale)
                              : t('supportAccess.history.never', 'Never')}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {isOwner && (
        <GrantSupportDialog open={granting} onOpenChange={setGranting} onGranted={() => mutate()} />
      )}
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(o) => !o && setRevoking(null)}
        title={t('supportAccess.revoke.title', 'Revoke support access?')}
        desc={t(
          'supportAccess.revoke.description',
          '{name} loses access at once, and a session in progress ends.',
          { name: revoking?.admin_name || revoking?.admin_email || '' }
        )}
        confirmText={t('supportAccess.revoke.confirm', 'Revoke access')}
        destructive
        isLoading={busy}
        handleConfirm={confirmRevoke}
      />
    </div>
  )
}
