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
import { ActionMenu } from '@/components/ui/action-menu'
import { CircleStop, MoreHorizontal, Pause, RefreshCw } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
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
import { ErrorState, KeyValueList, PageHeader, PageStack } from '@/features/shared'
import Link from '@/components/link'
import { Skeleton } from '@/components/ui/skeleton'
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
import { confirmName } from '@/lib/confirm-name'
import { formatDateTime } from '@/lib/app-locale'

type ProgramTab = 'targets' | 'entries' | 'exclusions' | 'rules' | 'notifications'

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
    userAgents: (p.rules.user_agents ?? []).join('\n'),
    // A program saved before the switch keeps it off until someone turns it on.
    identificationRequired: !!p.rules.identification_required,
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
  const [tab, setTab] = useState<ProgramTab | null>(null)

  if (error) {
    return (
      <Main>
        <PageStack>
          <ErrorState title={t('programs.one', 'program')} error={error} onRetry={() => mutate()} />
          <Button asChild variant="outline" size="sm" className="self-start">
            <Link href="/programs">{t('programs.back', 'Back to programs')}</Link>
          </Button>
        </PageStack>
      </Main>
    )
  }
  if (!p) {
    return (
      <Main>
        <PageStack>
          <Skeleton className="h-9 w-64" />
          <Skeleton className="h-24 w-full rounded-xl" />
          <Skeleton className="h-64 w-full" />
        </PageStack>
      </Main>
    )
  }
  if (p.locked) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={p.name} description={p.platform || undefined} />
          <ProgramLocked
            program={p}
            onAccepted={() => Promise.all([mutate(), invalidatePrograms()])}
          />
        </PageStack>
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
  const inScopeCount = p.items.filter((i) => i.in_scope).length
  const hasTargets = inScopeCount > 0
  const tabs: ProgramTab[] = [
    ...(hasTargets ? (['targets'] as const) : []),
    'entries',
    'exclusions',
    'rules',
    ...(p.visibility === 'private' ? (['notifications'] as const) : []),
  ]
  const current: ProgramTab = tab && tabs.includes(tab) ? tab : tabs[0]

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={p.name}
          // The status belongs to the name: on its line, never under the actions.
          titleAction={
            <Badge variant="secondary">
              {t(`programs.status.${p.status}`, PROGRAM_STATUS_LABEL[p.status])}
            </Badge>
          }
          description={
            <SafeExternalLink href={p.program_url} className="break-all underline">
              {p.program_url}
            </SafeExternalLink>
          }
        >
          {canWrite && p.status !== 'ended' && (
            <>
              <Button variant="outline" onClick={() => setReimport((x) => !x)} disabled={busy}>
                <RefreshCw aria-hidden />
                {t('programs.reimport', 'Re-import scope')}
              </Button>
              {/* Suspend and End (irreversible) wait behind "More actions": no
                  filled destructive button at rest. */}
              <ActionMenu
                title={p.name}
                label={t('common.actionMenu.more', 'More actions')}
                items={[
                  ...(p.status === 'active'
                    ? [
                        {
                          id: 'suspend',
                          label: t('programs.suspend', 'Suspend'),
                          icon: Pause,
                          onSelect: () => setPending('suspend'),
                        },
                      ]
                    : []),
                  {
                    id: 'end',
                    label: t('programs.end', 'End'),
                    icon: CircleStop,
                    destructive: true,
                    onSelect: () => setPending('end'),
                  },
                ]}
                trigger={
                  <Button
                    variant="outline"
                    size="icon"
                    disabled={busy}
                    aria-label={t('common.actionMenu.more', 'More actions')}
                  >
                    <MoreHorizontal aria-hidden />
                  </Button>
                }
              />
            </>
          )}
        </PageHeader>

        <>
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
              <h3 className="text-base font-semibold">
                {t('programs.reimport', 'Re-import scope')}
              </h3>
              <ProgramForm
                existing
                initial={formFromProgram(p)}
                submitLabel={t('programs.reimportSubmit', 'Accept and re-import')}
                onSubmit={(input) => reimportProgram(p.id, input)}
                onDone={() => {
                  setReimport(false)
                  toast.success(t('programs.reimported', 'Scope re-imported'))
                  void refresh()
                }}
              />
            </section>
          )}

          <ProgramPendingTerms program={p} canWrite={canWrite} onChanged={refresh} />
          <ProgramSuggestions program={p} canWrite={canWrite} onChanged={refresh} />

          {/* One job per tab (MVP v2): the targets table first, not under
              the rules, the scope source and the notifications. */}
          <Tabs value={current} onValueChange={(v) => setTab(v as ProgramTab)}>
            <TabsList>
              {hasTargets && (
                <TabsTrigger value="targets">
                  {t('programs.tab.targets', 'Targets')}
                  <TabsCount value={inScopeCount} />
                </TabsTrigger>
              )}
              <TabsTrigger value="entries">
                {t('programs.entries', 'Scope entries')}
                <TabsCount value={p.entries.length} />
              </TabsTrigger>
              <TabsTrigger value="exclusions">
                {t('programs.tab.exclusions', 'Exclusions')}
                <TabsCount value={p.exclusions.length} />
              </TabsTrigger>
              <TabsTrigger value="rules">{t('programs.tab.rules', 'Rules and source')}</TabsTrigger>
              {p.visibility === 'private' && (
                <TabsTrigger value="notifications">
                  {t('programs.notify.title', 'Notifications')}
                </TabsTrigger>
              )}
            </TabsList>
            {hasTargets && (
              <TabsContent value="targets">
                <ProgramTargetsTable items={p.items} error={error} onRetry={() => void mutate()} />
              </TabsContent>
            )}
            <TabsContent value="entries">
              <Table aria-label={t('programs.entries', 'Scope entries')}>
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
                          <Badge variant="outline" className="ml-2">
                            {t('programs.targets.onlyPorts', 'only {ports}', {
                              ports: portLimit(e.ports, e.protocol),
                            })}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">
                        {e.target_type}
                      </TableCell>
                      <TableCell>
                        <Badge variant={e.in_effect ? 'default' : 'secondary'}>
                          {e.in_effect ? t('programs.inEffect', 'In effect') : e.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TabsContent>
            <TabsContent value="exclusions">
              <ProgramExclusionsTable exclusions={p.exclusions} />
            </TabsContent>
            <TabsContent value="rules" className="flex flex-col gap-4">
              {/* The program's terms and rules: label and value pairs (the shared
                list), so a long value wraps under its label, not into rows of
                loose text. */}
              <KeyValueList
                items={[
                  {
                    key: 'terms',
                    label: t('programs.attestation', 'Accepted terms'),
                    value: (
                      <>
                        <span className="font-mono">{shortHash(p.terms_sha256)}</span>
                        {p.accepted_at && (
                          <span className="text-muted-foreground">
                            {' '}
                            ({formatDateTime(new Date(p.accepted_at))})
                          </span>
                        )}
                      </>
                    ),
                  },
                  {
                    key: 'tier',
                    label: t('programs.col.tier', 'Max tier'),
                    value: <span className="font-mono">{p.max_tier}</span>,
                  },
                  {
                    key: 'rate',
                    label: t('programs.form.rate', 'Rate limit (requests per second)'),
                    value: p.rules.rate_limit_rps || '-',
                  },
                  {
                    key: 'ua',
                    label: t('programs.form.ua', 'Required User-Agent'),
                    value: p.rules.user_agents?.length
                      ? t('programs.rotatingOver', 'Rotating over {n} values', {
                          n: p.rules.user_agents.length,
                        })
                      : p.rules.user_agent || '-',
                    token: !p.rules.user_agents?.length,
                  },
                  {
                    key: 'identification',
                    label: t('programs.identificationRequired', 'Identification required'),
                    value: p.rules.identification_required
                      ? t('common.yes', 'Yes')
                      : t('common.no', 'No'),
                  },
                  {
                    key: 'windows',
                    label: t('programs.windows', 'Testing windows'),
                    value: p.rules.testing_windows?.length ? (
                      <span className="font-mono text-xs">
                        {p.rules.testing_windows.map(formatWindow).join('; ')}
                      </span>
                    ) : (
                      t('programs.windowsAny', 'Any time')
                    ),
                  },
                  {
                    key: 'forbidden',
                    label: t('programs.form.forbidden', 'The program forbids'),
                    value:
                      FORBIDDEN_TECHNIQUES.filter((f) => forbidden.has(f.value))
                        .map((f) => t(`programs.forbidden.${f.value}`, f.label))
                        .join(', ') || '-',
                  },
                ]}
              />
              <ProgramSource program={p} canWrite={canWrite} onChanged={refresh} />
            </TabsContent>
            {p.visibility === 'private' && (
              <TabsContent value="notifications">
                <ProgramNotifications
                  program={p}
                  canManage={canWrite && canManageIntegrations}
                  isOwner={isOwner()}
                />
              </TabsContent>
            )}
          </Tabs>
        </>
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
          typeToConfirm={pending === 'end' ? confirmName(p.name, p.id) : undefined}
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
      </PageStack>
    </Main>
  )
}
