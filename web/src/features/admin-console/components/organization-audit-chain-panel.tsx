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
import { AdminApiError } from '../api/admin-client'
import {
  AUDIT_CHAIN_ERROR,
  rebaselineAuditChain,
  useAuditChainStatus,
} from '../api/use-admin-audit-chain'

const CLASS_LABEL: Record<AuditChainClass, string> = {
  verifies: 'Verifies',
  legacy_truncate: 'Legacy timestamp truncation',
  pre_79_nanosecond: 'Pre-#79 nanosecond hash',
  unexplained: 'Unexplained',
  source_missing: 'Audit log missing',
  link_broken: 'Broken link',
}

const BLOCKING: ReadonlySet<AuditChainClass> = new Set([
  'unexplained',
  'source_missing',
  'link_broken',
])

function ClassBadge({ value }: { value?: AuditChainClass }) {
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
      {CLASS_LABEL[value] ?? value}
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
  const { data, error, isLoading, isValidating, mutate } = useAuditChainStatus(tenantId)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [code, setCode] = useState('')
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
      toast.success(`Audit chain rebaselined: ${res.entries_rewritten ?? 0} entries re-signed`)
      void mutate()
    } catch (e) {
      if (!(e instanceof AdminApiError)) {
        toast.error('Could not rebaseline the audit chain')
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
    return <ErrorState title="the audit chain" error={error} onRetry={recheck} />
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
            <CardTitle>Audit chain</CardTitle>
            <CardDescription>
              Every audit log entry is hash-chained to the one before it, so an edited or deleted
              entry shows up as a break. Each break is checked against the known timestamp-hashing
              defects; anything they do not explain could be tampering.
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
            Re-check
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
                  title={`${blocking} ${blocking === 1 ? 'break' : 'breaks'} no known defect explains`}
                >
                  Do not rebaseline: it would erase the difference between a hashing defect and
                  tampering. Investigate the entries below first.
                </DetailCallout>
              ) : breaks > 0 ? (
                <DetailCallout
                  tone="warning"
                  icon={AlertTriangle}
                  title={`${breaks} ${breaks === 1 ? 'break' : 'breaks'}, all explained by a known hashing defect`}
                >
                  They were left by the old timestamp-precision bug, not by an edit. Until the chain
                  is rebaselined they hide any new break from verification.
                </DetailCallout>
              ) : null}

              <DetailStatGrid>
                <DetailStat label="Entries" value={total} />
                <DetailStat label="Verify" value={counts.verifies ?? 0} />
                <DetailStat
                  label="Explained breaks"
                  value={explained}
                  caption={
                    explained > 0
                      ? `${counts.legacy_truncate ?? 0} legacy, ${counts.pre_79_nanosecond ?? 0} pre-#79`
                      : undefined
                  }
                />
                <DetailStat
                  label="Unexplained"
                  value={blocking}
                  tone={blocking > 0 ? 'destructive' : 'default'}
                />
              </DetailStatGrid>

              <p className="text-xs text-muted-foreground">
                Checked <RelativeTime date={data.classified_at} className="text-xs" />
              </p>

              {samples.length > 0 && (
                <section className="space-y-2">
                  <h3 className="text-sm font-semibold">Entries that do not verify</h3>
                  <div className="overflow-x-auto rounded-lg border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-24">Position</TableHead>
                          <TableHead>Why</TableHead>
                          <TableHead>Action</TableHead>
                          <TableHead>Logged</TableHead>
                          <TableHead>Audit log</TableHead>
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
                                <DetailCopyId id={s.audit_log_id} label="Audit log ID" />
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {samples.length < breaks && (
                    <p className="text-xs text-muted-foreground">
                      Showing every unexplained entry and a few examples of each explained kind.
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
          title={`Rebaselined: ${result.entries_rewritten ?? 0} of ${result.entries_total ?? 0} entries re-signed`}
          label="Rebaseline result"
        >
          {result.verify
            ? result.verify.ok
              ? `Verification now passes: ${result.verify.verified ?? 0} of ${result.verify.total ?? 0} entries, 0 breaks.`
              : `Verification still reports ${result.verify.breaks ?? 0} breaks. Re-check the chain.`
            : 'Re-check the chain to confirm it verifies.'}{' '}
          The previous hashes are archived under rebaseline{' '}
          {result.rebaseline_id && <DetailCopyId id={result.rebaseline_id} label="Rebaseline ID" />}
        </DetailCallout>
      )}

      <DangerZone>
        <DangerZoneItem
          title="Rebaseline audit chain"
          description={
            <>
              Re-signs every entry from the current audit log, so the explained breaks stop hiding
              new ones. It cannot be undone; the old hashes are archived.
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
              Rebaseline
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
        title="Rebaseline the audit chain?"
        desc={
          <div className="space-y-2">
            <p>
              This re-signs all {total} entries of {orgName}&apos;s audit chain from the current
              audit log. The {explained} explained {explained === 1 ? 'break' : 'breaks'} will
              verify afterwards, and so would any edit made before now: it is irreversible.
            </p>
            <p>
              The server checks the chain again and refuses if anything is unexplained or the chain
              changed since this review. The action is recorded in the organization&apos;s audit log
              and the platform audit log.
            </p>
          </div>
        }
        typeToConfirm={orgName}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              Rebaselining
            </>
          ) : (
            'Rebaseline'
          )
        }
        isLoading={busy}
        disabled={!/^\d{6}$/.test(code.trim())}
        handleConfirm={() => void rebaseline()}
      >
        <div className="space-y-2">
          <Label htmlFor={codeId} className="font-normal">
            Code from your authenticator
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
          {codeError ? (
            <p id={`${codeId}-error`} className="text-sm text-destructive">
              {codeError}
            </p>
          ) : (
            <p className="text-xs text-muted-foreground">
              A new code: the one you signed in with cannot be used again.
            </p>
          )}
        </div>
      </ConfirmDialog>
    </div>
  )
}
