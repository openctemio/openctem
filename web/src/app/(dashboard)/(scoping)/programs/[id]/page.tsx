'use client'

/**
 * One program (RFC-065): its attestation, rules, scope entries and program
 * exclusions (with any overlap with the organization's own scope), and the
 * lifecycle: re-import, suspend, reactivate (a new attestation of the
 * current terms), end. A program the caller may not see is "not found".
 */

import { use, useState } from 'react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { SafeExternalLink } from '@/components/safe-external-link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import { Permission, useHasPermission, usePermissions } from '@/lib/permissions'
import { ErrorState, PageHeader } from '@/features/shared'
import {
  EMPTY_PROGRAM_FORM,
  FORBIDDEN_TECHNIQUES,
  PROGRAM_STATUS_LABEL,
  ProgramExclusionsTable,
  ProgramForm,
  ProgramLocked,
  ProgramNotifications,
  ProgramPendingTerms,
  ProgramSource,
  ProgramSuggestions,
  endProgram,
  formatWindow,
  invalidatePrograms,
  portLimit,
  ProgramTargetsTable,
  reactivateProgram,
  reimportProgram,
  shortHash,
  suspendProgram,
  useProgram,
  type ProgramDetail,
  type ProgramFormValues,
} from '@/features/programs'

function formFromProgram(p: ProgramDetail): ProgramFormValues {
  const lines = (inScope: boolean) =>
    p.items
      .filter((i) => i.in_scope === inScope)
      .map((i) => i.raw)
      .join('\n')
  const out = lines(false)
  return {
    ...EMPTY_PROGRAM_FORM,
    name: p.name,
    platform: p.platform,
    handle: p.handle,
    programUrl: p.program_url,
    scopeText: out ? `In scope\n${lines(true)}\n\nOut of scope\n${out}\n` : `${lines(true)}\n`,
    rateLimit: p.rules.rate_limit_rps ? String(p.rules.rate_limit_rps) : '',
    headers: (p.rules.required_headers ?? []).map((h) => `${h.name}: ${h.value}`).join('\n'),
    userAgent: p.rules.user_agent ?? '',
    forbidden: p.rules.forbidden ?? [],
    notes: p.rules.notes ?? '',
    windows: (p.rules.testing_windows ?? []).map(formatWindow).join('\n'),
    termsText: p.terms_text ?? '',
    visibility: p.visibility,
  }
}

export default function ProgramPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.ProgramsWrite)
  const canManageIntegrations = useHasPermission(Permission.IntegrationsManage)
  const { isOwner } = usePermissions()
  const { data: p, error, mutate } = useProgram(id)
  const [reimport, setReimport] = useState(false)
  const [reattest, setReattest] = useState(false)
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<'suspend' | 'end' | null>(null)

  if (error) {
    return (
      <Main>
        <ErrorState title={t('programs.one', 'program')} error={error} />
      </Main>
    )
  }
  if (!p) return <Main />
  if (p.locked) {
    return (
      <Main>
        <PageHeader title={p.name} description={p.platform || undefined} />
        <ProgramLocked
          program={p}
          onAccepted={() => Promise.all([mutate(), invalidatePrograms()])}
        />
      </Main>
    )
  }

  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true)
    try {
      await fn()
      toast.success(done)
      setReattest(false)
      setPending(null)
      await Promise.all([mutate(), invalidatePrograms()])
    } catch (err) {
      toast.error(
        err instanceof ApiClientError ? err.message : t('programs.failed', 'The change failed')
      )
    } finally {
      setBusy(false)
    }
  }

  const forbidden = new Set(p.rules.forbidden ?? [])
  const refresh = () => Promise.all([mutate(), invalidatePrograms()])

  return (
    <Main>
      <PageHeader
        title={p.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Badge variant={p.status === 'active' ? 'default' : 'secondary'}>
              {t(`programs.status.${p.status}`, PROGRAM_STATUS_LABEL[p.status])}
            </Badge>
            <SafeExternalLink href={p.program_url} className="text-sm underline">
              {p.program_url}
            </SafeExternalLink>
          </span>
        }
      >
        {canWrite && p.status !== 'ended' && (
          <>
            <Button variant="outline" onClick={() => setReimport((x) => !x)} disabled={busy}>
              {t('programs.reimport', 'Re-import scope')}
            </Button>
            {p.status === 'active' && (
              <Button variant="outline" disabled={busy} onClick={() => setPending('suspend')}>
                {t('programs.suspend', 'Suspend')}
              </Button>
            )}
            <Button variant="destructive" disabled={busy} onClick={() => setPending('end')}>
              {t('programs.end', 'End')}
            </Button>
          </>
        )}
      </PageHeader>

      <div className="space-y-6">
        {(p.status === 'paused' || p.status === 'pending_attestation') && canWrite && (
          <section className="space-y-3 rounded-md border p-4">
            <p className="text-sm">
              {p.status === 'pending_attestation'
                ? t(
                    'programs.acceptHint',
                    'Only passive monitoring runs until someone accepts this program rules and scope (terms {hash}); its entries authorize no active scan until then.',
                    { hash: shortHash(p.terms_sha256) }
                  )
                : t(
                    'programs.reactivateHint',
                    'Suspended: its entries authorize nothing. Reactivating accepts the program terms again (terms {hash}).',
                    { hash: shortHash(p.terms_sha256) }
                  )}
            </p>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={reattest} onCheckedChange={(c) => setReattest(c === true)} />
              {t('programs.reattest', 'I accept this program rules and scope again')}
            </label>
            <Button
              disabled={busy || !reattest}
              onClick={() =>
                act(
                  () => reactivateProgram(p.id, p.terms_sha256),
                  t('programs.reactivated', 'Program reactivated')
                )
              }
            >
              {p.status === 'pending_attestation'
                ? t('programs.acceptStart', 'Accept and start testing')
                : t('programs.reactivate', 'Reactivate')}
            </Button>
          </section>
        )}

        {reimport && (
          <section className="space-y-2">
            <h3 className="text-base font-semibold">{t('programs.reimport', 'Re-import scope')}</h3>
            <ProgramForm
              existing
              initial={formFromProgram(p)}
              submitLabel={t('programs.reimportSubmit', 'Accept and re-import')}
              onSubmit={(input) => reimportProgram(p.id, input)}
              onDone={() => {
                setReimport(false)
                toast.success(t('programs.reimported', 'Scope re-imported'))
                void mutate()
              }}
            />
          </section>
        )}

        <section className="grid gap-2 text-sm sm:grid-cols-2">
          <div>
            <span className="text-muted-foreground">
              {t('programs.attestation', 'Accepted terms')}:{' '}
            </span>
            <span className="font-mono">{shortHash(p.terms_sha256)}</span>
            {p.accepted_at && (
              <span className="text-muted-foreground">
                {' '}
                ({new Date(p.accepted_at).toLocaleString()})
              </span>
            )}
          </div>
          <div>
            <span className="text-muted-foreground">{t('programs.col.tier', 'Max tier')}: </span>
            <span className="font-mono">{p.max_tier}</span>
          </div>
          <div>
            <span className="text-muted-foreground">
              {t('programs.form.rate', 'Rate limit (requests per second)')}:{' '}
            </span>
            {p.rules.rate_limit_rps || '-'}
          </div>
          <div>
            <span className="text-muted-foreground">
              {t('programs.form.ua', 'Required User-Agent')}:{' '}
            </span>
            <span className="font-mono">{p.rules.user_agent || '-'}</span>
          </div>
          <div className="sm:col-span-2">
            <span className="text-muted-foreground">
              {t('programs.windows', 'Testing windows')}:{' '}
            </span>
            {p.rules.testing_windows?.length ? (
              <span className="font-mono text-xs">
                {p.rules.testing_windows.map(formatWindow).join('; ')}
              </span>
            ) : (
              t('programs.windowsAny', 'Any time')
            )}
          </div>
          <div className="sm:col-span-2">
            <span className="text-muted-foreground">
              {t('programs.form.forbidden', 'The program forbids')}:{' '}
            </span>
            {FORBIDDEN_TECHNIQUES.filter((f) => forbidden.has(f.value))
              .map((f) => t(`programs.forbidden.${f.value}`, f.label))
              .join(', ') || '-'}
          </div>
        </section>

        <ProgramPendingTerms program={p} canWrite={canWrite} onChanged={refresh} />
        <ProgramSuggestions program={p} canWrite={canWrite} onChanged={refresh} />

        <ProgramSource program={p} canWrite={canWrite} onChanged={refresh} />

        {p.items.some((i) => i.in_scope) && (
          <section className="space-y-2">
            <h3 className="text-base font-semibold">
              {t('programs.targets.title', 'Program targets')}
            </h3>
            <ProgramTargetsTable items={p.items} />
          </section>
        )}
        <ProgramNotifications
          program={p}
          canManage={canWrite && canManageIntegrations}
          isOwner={isOwner()}
        />

        <section className="space-y-2">
          <h3 className="text-base font-semibold">{t('programs.entries', 'Scope entries')}</h3>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('programs.preview.target', 'In scope')}</TableHead>
                <TableHead>{t('programs.preview.type', 'Type')}</TableHead>
                <TableHead>{t('programs.col.status', 'Status')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {p.entries.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="font-mono text-xs break-all">
                    {e.pattern}
                    {portLimit(e.ports, e.protocol) && (
                      <Badge variant="outline" className="ml-2 font-mono">
                        {t('programs.targets.onlyPorts', 'only {ports}', {
                          ports: portLimit(e.ports, e.protocol),
                        })}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">{e.target_type}</TableCell>
                  <TableCell>
                    <Badge variant={e.in_effect ? 'default' : 'secondary'}>
                      {e.in_effect ? t('programs.inEffect', 'In effect') : e.status}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>

        <section className="space-y-2">
          <h3 className="text-base font-semibold">
            {t('programs.exclusions', 'Program exclusions')}
          </h3>
          <ProgramExclusionsTable exclusions={p.exclusions} />
        </section>
      </div>
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => !open && setPending(null)}
        destructive
        title={
          pending === 'end'
            ? t('confirm.program.endTitle', 'End the program "{name}"?', { name: p.name })
            : t('confirm.program.suspendTitle', 'Suspend the program "{name}"?', { name: p.name })
        }
        desc={
          pending === 'end'
            ? t(
                'confirm.program.endDesc',
                'Its scope entries stop authorizing scans at once and the program can no longer be changed or reactivated. Findings and history stay.'
              )
            : t(
                'confirm.program.suspendDesc',
                'Its scope entries stop authorizing scans until someone reactivates it and accepts the program terms again.'
              )
        }
        confirmText={
          pending === 'end'
            ? t('confirm.program.end', 'End program')
            : t('confirm.program.suspend', 'Suspend')
        }
        isLoading={busy}
        handleConfirm={() =>
          pending === 'end'
            ? act(() => endProgram(p.id), t('programs.ended', 'Program ended'))
            : pending === 'suspend'
              ? act(() => suspendProgram(p.id), t('programs.suspended', 'Program suspended'))
              : undefined
        }
      />
    </Main>
  )
}
