'use client'

import { useId, useState } from 'react'
import { AlertTriangle, CheckCircle2, Loader2, RefreshCw, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
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
import {
  DangerZone,
  DangerZoneItem,
  DetailCallout,
  DetailCopyId,
  DetailStat,
  DetailStatGrid,
  ErrorState,
  RelativeTime,
} from '@/features/shared'
import type {
  AdminAuditChainRebaselineResponse,
  AdminAuditChainStatusResponse,
  AuditChainClass,
} from '@/lib/api/generated'
import { cn } from '@/lib/utils'
import { AdminApiError } from '@console/lib/admin-api/client'
import {
  AUDIT_CHAIN_ERROR,
  rebaselineAuditChain,
  useAuditChainStatus,
} from '../api/use-admin-audit-chain'
import { useTranslation } from '@/context/i18n-provider'
import { StepUpCodeHint, stepUpCodeReady, useStepUpCodeOptional } from './step-up-code-hint'

const CLASS_KEY: Record<AuditChainClass, string> = {
  verifies: 'admin.auditChain.class.verifies',
  legacy_truncate: 'admin.auditChain.class.legacyTruncate',
  pre_79_nanosecond: 'admin.auditChain.class.pre79Nanosecond',
  unexplained: 'admin.auditChain.class.unexplained',
  source_missing: 'admin.auditChain.class.sourceMissing',
  link_broken: 'admin.auditChain.class.linkBroken',
}

const BLOCKING: ReadonlySet<AuditChainClass> = new Set([
  'unexplained',
  'source_missing',
  'link_broken',
])

function ClassBadge({ value }: { value?: AuditChainClass }) {
  const { t } = useTranslation()
  if (!value) return null
  const blocking = BLOCKING.has(value)
  return (
    <Badge
      variant="outline"
      className={cn(
        'font-normal',
        blocking
          ? 'border-destructive/40 bg-destructive/10 text-destructive'
          : 'text-muted-foreground'
      )}
    >
      {CLASS_KEY[value] ? t(CLASS_KEY[value]) : value}
    </Badge>
  )
}

interface OrganizationAuditChainPanelProps {
  tenantId: string
  /** The organization's name: the rebaseline confirmation must type it. */
  orgName: string
  /** Rebaselining needs a super admin; everyone else can review. */
  canRebaseline: boolean
}

/**
 * The organization's tamper-evident audit hash-chain: how many entries verify,
 * how many breaks a known hashing defect explains, and how many nothing
 * explains. When every break is explained, a super admin can rebaseline
 * (re-sign) the chain so verification catches new tampering again.
 */
export function OrganizationAuditChainPanel({
  tenantId,
  orgName,
  canRebaseline,
}: OrganizationAuditChainPanelProps) {
  const { t } = useTranslation()
  const { data, error, isLoading, isValidating, mutate } = useAuditChainStatus(tenantId)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [code, setCode] = useState('')
  const codeOptional = useStepUpCodeOptional()
  const [codeError, setCodeError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<AdminAuditChainRebaselineResponse | null>(null)
  const codeId = useId()

  const recheck = () => void mutate()

  const openConfirm = () => {
    setCode('')
    setCodeError(null)
    setConfirmOpen(true)
  }

  const rebaseline = async () => {
    if (!data?.fingerprint) return
    setBusy(true)
    setCodeError(null)
    try {
      const res = await rebaselineAuditChain(tenantId, {
        fingerprint: data.fingerprint,
        totp_code: code.trim(),
      })
      setResult(res)
      setConfirmOpen(false)
      toast.success(
        t(
          'admin.organizationAuditChainPanel.rebaselinedToast',
          'Audit chain rebaselined: {count} entries re-signed',
          { count: res.entries_rewritten ?? 0 }
        )
      )
      void mutate()
    } catch (e) {
      if (!(e instanceof AdminApiError)) {
        toast.error(
          t(
            'admin.organizationAuditChainPanel.couldNotRebaselineTheAudit',
            'Could not rebaseline the audit chain'
          )
        )
        return
      }
      if (e.status === 401) {
        // Wrong, reused or missing code: stay in the dialog.
        setCodeError(e.message)
        setCode('')
        return
      }
      setConfirmOpen(false)
      if (e.code === AUDIT_CHAIN_ERROR.unexplained || e.code === AUDIT_CHAIN_ERROR.changed) {
        // Show what the server saw when it refused; nothing was changed.
        const seen = e.details as AdminAuditChainStatusResponse | undefined
        if (seen?.fingerprint) {
          void mutate(seen, { revalidate: false })
        } else {
          void mutate()
        }
      } else {
        void mutate()
      }
      toast.error(e.message)
    } finally {
      setBusy(false)
    }
  }

  if (error) {
    return (
      <ErrorState
        title={t('admin.organizationAuditChainPanel.theAuditChain', 'the audit chain')}
        error={error}
        onRetry={recheck}
      />
    )
  }

  const counts = data?.counts ?? {}
  const total = data?.total ?? 0
  const breaks = data?.breaks ?? 0
  const blocking = data?.blocking ?? 0
  const explained = (counts.legacy_truncate ?? 0) + (counts.pre_79_nanosecond ?? 0)
  const samples = data?.samples ?? []
  const canRun = canRebaseline && !!data?.rebaseline_allowed && breaks > 0 && !!data?.fingerprint

  let disabledReason: string | null = null
  if (!canRebaseline) disabledReason = 'Rebaselining requires a super admin.'
  else if (data && blocking > 0) disabledReason = 'Refused while any break is unexplained.'
  else if (data && breaks === 0)
    disabledReason = 'Every entry verifies: there is nothing to rebaseline.'

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
          <div className="space-y-1.5">
            <CardTitle>
              {t('admin.organizationAuditChainPanel.auditChain', 'Audit chain')}
            </CardTitle>
            <CardDescription>
              {t(
                'admin.organizationAuditChainPanel.everyAuditLogEntryIs',
                'Every audit log entry is hash-chained to the one before it, so an edited or deleted entry shows up as a break. Each break is checked against the known timestamp-hashing defects; anything they do not explain could be tampering.'
              )}
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={recheck}
            disabled={isLoading || isValidating}
            className="shrink-0"
          >
            <RefreshCw className={cn('me-1.5 size-4', isValidating && 'animate-spin')} />
            {t('admin.organizationAuditChainPanel.recheck', 'Re-check')}
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          {isLoading || !data ? (
            <div className="space-y-3">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : (
            <>
              {blocking > 0 ? (
                <DetailCallout
                  tone="destructive"
                  icon={ShieldAlert}
                  title={
                    blocking === 1
                      ? t(
                          'admin.organizationAuditChainPanel.unexplainedBreakOne',
                          '{count} break no known defect explains',
                          { count: blocking }
                        )
                      : t(
                          'admin.organizationAuditChainPanel.unexplainedBreakMany',
                          '{count} breaks no known defect explains',
                          { count: blocking }
                        )
                  }
                >
                  {t(
                    'admin.organizationAuditChainPanel.doNotRebaselineItWould',
                    'Do not rebaseline: it would erase the difference between a hashing defect and tampering. Investigate the entries below first.'
                  )}
                </DetailCallout>
              ) : breaks > 0 ? (
                <DetailCallout
                  tone="warning"
                  icon={AlertTriangle}
                  title={
                    breaks === 1
                      ? t(
                          'admin.organizationAuditChainPanel.explainedBreakOne',
                          '{count} break, all explained by a known hashing defect',
                          { count: breaks }
                        )
                      : t(
                          'admin.organizationAuditChainPanel.explainedBreakMany',
                          '{count} breaks, all explained by a known hashing defect',
                          { count: breaks }
                        )
                  }
                >
                  {t(
                    'admin.organizationAuditChainPanel.theyWereLeftByThe',
                    'They were left by the old timestamp-precision bug, not by an edit. Until the chain is rebaselined they hide any new break from verification.'
                  )}
                </DetailCallout>
              ) : null}

              <DetailStatGrid>
                <DetailStat
                  label={t('admin.organizationAuditChainPanel.entries', 'Entries')}
                  value={total}
                />
                <DetailStat
                  label={t('admin.organizationAuditChainPanel.verify', 'Verify')}
                  value={counts.verifies ?? 0}
                />
                <DetailStat
                  label={t('admin.organizationAuditChainPanel.explainedBreaks', 'Explained breaks')}
                  value={explained}
                  caption={
                    explained > 0
                      ? `${counts.legacy_truncate ?? 0} legacy, ${counts.pre_79_nanosecond ?? 0} pre-#79`
                      : undefined
                  }
                />
                <DetailStat
                  label={t('admin.organizationAuditChainPanel.unexplained', 'Unexplained')}
                  value={blocking}
                  tone={blocking > 0 ? 'destructive' : 'default'}
                />
              </DetailStatGrid>

              <p className="text-xs text-muted-foreground">
                {t('admin.organizationAuditChainPanel.checked', 'Checked')}{' '}
                <RelativeTime date={data.classified_at} className="text-xs" />
              </p>

              {samples.length > 0 && (
                <section className="space-y-2">
                  <h3 className="text-sm font-semibold">
                    {t(
                      'admin.organizationAuditChainPanel.entriesThatDoNotVerify',
                      'Entries that do not verify'
                    )}
                  </h3>
                  <div className="overflow-x-auto rounded-lg border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-24">
                            {t('admin.organizationAuditChainPanel.position', 'Position')}
                          </TableHead>
                          <TableHead>{t('admin.organizationAuditChainPanel.why', 'Why')}</TableHead>
                          <TableHead>
                            {t('admin.organizationAuditChainPanel.action', 'Action')}
                          </TableHead>
                          <TableHead>
                            {t('admin.organizationAuditChainPanel.logged', 'Logged')}
                          </TableHead>
                          <TableHead>
                            {t('admin.organizationAuditChainPanel.auditLog', 'Audit log')}
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {samples.map((s) => (
                          <TableRow key={`${s.position}-${s.audit_log_id}`}>
                            <TableCell className="tabular-nums">{s.position}</TableCell>
                            <TableCell>
                              <ClassBadge value={s.class} />
                            </TableCell>
                            <TableCell className="text-sm">{s.action || '—'}</TableCell>
                            <TableCell>
                              <RelativeTime date={s.logged_at} />
                            </TableCell>
                            <TableCell>
                              {s.audit_log_id && (
                                <DetailCopyId
                                  id={s.audit_log_id}
                                  label={t(
                                    'admin.organizationAuditChainPanel.auditLogId',
                                    'Audit log ID'
                                  )}
                                />
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {samples.length < breaks && (
                    <p className="text-xs text-muted-foreground">
                      {t(
                        'admin.organizationAuditChainPanel.showingEveryUnexplainedEntryAnd',
                        'Showing every unexplained entry and a few examples of each explained kind.'
                      )}
                    </p>
                  )}
                </section>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {result && (
        <DetailCallout
          tone="info"
          icon={CheckCircle2}
          title={t(
            'admin.organizationAuditChainPanel.rebaselinedResult',
            'Rebaselined: {done} of {total} entries re-signed',
            {
              done: result.entries_rewritten ?? 0,
              total: result.entries_total ?? 0,
            }
          )}
          label={t('admin.organizationAuditChainPanel.rebaselineResult', 'Rebaseline result')}
        >
          {result.verify
            ? result.verify.ok
              ? t(
                  'admin.organizationAuditChainPanel.verifyPasses',
                  'Verification now passes: {verified} of {total} entries, 0 breaks.',
                  {
                    verified: result.verify.verified ?? 0,
                    total: result.verify.total ?? 0,
                  }
                )
              : t(
                  'admin.organizationAuditChainPanel.verifyStillBreaks',
                  'Verification still reports {count} breaks. Re-check the chain.',
                  {
                    count: result.verify.breaks ?? 0,
                  }
                )
            : t(
                'admin.organizationAuditChainPanel.reCheckTheChainTo',
                'Re-check the chain to confirm it verifies.'
              )}{' '}
          {t(
            'admin.organizationAuditChainPanel.thePreviousHashesAreArchived',
            'The previous hashes are archived under the rebaseline ID.'
          )}{' '}
          {result.rebaseline_id && (
            <DetailCopyId
              id={result.rebaseline_id}
              label={t('admin.organizationAuditChainPanel.rebaselineId', 'Rebaseline ID')}
            />
          )}
        </DetailCallout>
      )}

      <DangerZone>
        <DangerZoneItem
          title={t(
            'admin.organizationAuditChainPanel.rebaselineAuditChain',
            'Rebaseline audit chain'
          )}
          description={
            <>
              {t(
                'admin.organizationAuditChainPanel.reSignsEveryEntryFrom',
                'Re-signs every entry from the current audit log, so the explained breaks stop hiding new ones. It cannot be undone; the old hashes are archived.'
              )}
              {disabledReason && <span className="mt-1 block">{disabledReason}</span>}
            </>
          }
          action={
            <Button
              variant="destructive"
              size="sm"
              disabled={!canRun || busy}
              onClick={openConfirm}
            >
              {t('admin.organizationAuditChainPanel.rebaseline', 'Rebaseline')}
            </Button>
          }
        />
      </DangerZone>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!busy) setConfirmOpen(open)
        }}
        destructive
        title={t('confirm.auditChain.rebaselineTitle', 'Rebaseline the audit chain of {org}?', {
          org: orgName ?? '',
        })}
        desc={
          <div className="space-y-2">
            <p>
              {t(
                'confirm.auditChain.rebaselineDesc',
                'This re-signs all {total} entries of the audit chain from the current audit log. The {explained} explained breaks will verify afterwards, and so would any edit made before now: it is irreversible.',
                { total, explained }
              )}
            </p>
            <p>
              {t(
                'confirm.auditChain.rebaselineCheck',
                'The server checks the chain again and refuses if anything is unexplained or the chain changed since this review. The action is recorded in the organization audit log and the platform audit log.'
              )}
            </p>
          </div>
        }
        typeToConfirm={orgName}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('confirm.auditChain.rebaselining', 'Rebaselining…')}
            </>
          ) : (
            t('confirm.auditChain.rebaseline', 'Rebaseline')
          )
        }
        isLoading={busy}
        disabled={!stepUpCodeReady(code, codeOptional)}
        handleConfirm={() => void rebaseline()}
      >
        <div className="space-y-2">
          <Label htmlFor={codeId} className="font-normal">
            {t('confirm.auditChain.code', 'Code from your authenticator')}
          </Label>
          <Input
            id={codeId}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            className="tabular-nums"
            aria-invalid={codeError ? true : undefined}
            aria-describedby={codeError ? `${codeId}-error` : undefined}
          />
          <StepUpCodeHint optional={codeOptional} />
          {codeError ? (
            <p id={`${codeId}-error`} className="text-sm text-destructive">
              {codeError}
            </p>
          ) : (
            <p className="text-xs text-muted-foreground">
              {t(
                'admin.organizationAuditChainPanel.aNewCodeTheOne',
                'A new code: the one you signed in with cannot be used again.'
              )}
            </p>
          )}
        </div>
      </ConfirmDialog>
    </div>
  )
}
