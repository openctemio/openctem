'use client'

/**
 * The CI/CD page's Connections tab (api RFC-051): whether CI works first
 * (one status line), then one line per trust configuration. A line opens the
 * configuration in a sheet: Health (refused jobs with one-click fixes), Rules
 * (the editor, rare rules folded), Scope (its repository scope entries) and
 * the pipeline snippet. The organization-wide "Require OIDC" switch is folded
 * at the end. The one way to add a configuration is the page's "Connect a CI
 * provider". Writes need scans:ci:write; the API is the authority.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  KeyRound,
  Trash2,
} from 'lucide-react'
import {
  DetailHeader,
  DetailSheet,
  DetailTabs,
  EmptyState,
  ErrorState,
  RelativeTime,
} from '@/features/shared'
import { ProviderIcon } from '@/features/scm-connections'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { confirmName } from '@/lib/confirm-name'
import { useTranslation } from '@/context/i18n-provider'
import { formatLocalized } from '@/lib/format-date'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { useUrlFilter } from '@/hooks/use-url-param'
import { cn } from '@/lib/utils'
import {
  useCISettings,
  useDeleteTrustConfig,
  useTrustConfigs,
  useTrustRefusals,
} from '../api/use-ci'
import { PROVIDER_LABEL, joinList } from '../lib/ci'
import { configNames, refusalsOf, type RefusalFix } from '../lib/connect'
import type { CITokenRefusal, CITrustConfig } from '../types'
import { CIRequireOIDC } from './ci-require-oidc'
import { CITrustScopeEntries, manageScopeSupported } from './ci-trust-scope'
import { CITrustRefusals, RefusalDetail, recentRefusals } from './ci-refusals'
import { SnippetPanel, TrustConfigForm } from './ci-trust-form'

type TFn = ReturnType<typeof useTranslation>['t']

/** The tabs of a configuration's sheet. */
export const TRUST_SHEET_TABS = ['health', 'rules', 'scope', 'snippet'] as const
export type TrustSheetTab = (typeof TRUST_SHEET_TABS)[number]

/** The rules of a configuration in one line. */
export function rulesSummary(c: CITrustConfig, t: TFn): string {
  const r = c.rules ?? {}
  const parts: string[] = []
  const add = (key: string, fallback: string, list?: string[]) => {
    if (list?.length) parts.push(t(key, fallback, { list: joinList(list) }))
  }
  add('scans.ci.trust.sumOwners', 'owners {list}', r.owners)
  add('scans.ci.trust.sumRepositories', 'repositories {list}', r.repositories)
  add('scans.ci.trust.sumRefs', 'refs {list}', r.refs)
  add('scans.ci.trust.sumEnvironments', 'environments {list}', r.environments)
  add('scans.ci.trust.sumEvents', 'events {list}', r.events)
  add('scans.ci.trust.sumWorkflowRefs', 'pipeline definitions {list}', r.workflow_refs)
  if (r.require_protected_ref)
    parts.push(t('scans.ci.trust.sumProtected', 'protected branches only'))
  return parts.join(', ')
}

/** A configuration works when it is on and has let a job in. */
export function isWorking(c: CITrustConfig): boolean {
  return c.enabled !== false && !!c.last_used_at
}

/** The newest accepted job over every configuration ('' for none). */
export function lastAccepted(configs: CITrustConfig[]): string {
  return configs.reduce(
    (best, c) =>
      c.last_used_at && (!best || Date.parse(c.last_used_at) > Date.parse(best))
        ? c.last_used_at
        : best,
    ''
  )
}

export function CIConnections() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.CIWrite)
  const { data, error, isLoading, mutate } = useTrustConfigs()
  const configs = useMemo(() => data?.data ?? [], [data])
  const refusals = useTrustRefusals({ enabled: canWrite })
  const refusedList = useMemo(() => refusals.data?.data ?? [], [refusals.data])
  // The clock is read once per mount; a render must not change the answer.
  const [now] = useState(() => Date.now())
  const recent = useMemo(() => recentRefusals(refusedList, now), [refusedList, now])
  // The open sheet lives in the URL, so a notification or a link can open it.
  const [openId, setOpenId] = useUrlFilter('connection', '')
  const [refusedParam, setRefusedParam] = useUrlFilter('refused', '')
  const open = configs.find((c) => c.id === openId) ?? null
  const [sheetTab, setSheetTab] = useState<TrustSheetTab>('health')
  const [fix, setFix] = useState<RefusalFix | null>(null)

  const openConfig = (c: CITrustConfig, tab: TrustSheetTab = 'health', f?: RefusalFix) => {
    setRefusedParam('')
    setFix(f ?? null)
    setSheetTab(tab)
    setOpenId(c.id ?? '')
  }
  /** The configuration a refusal's fix edits: the one naming its project, else the only one of its provider. */
  const targetOf = (r: CITokenRefusal): CITrustConfig | undefined => {
    const named = configs.find((c) => configNames(c, r.repository ?? '', r.provider))
    if (named) return named
    const same = configs.filter((c) => c.provider === r.provider)
    return same.length === 1 ? same[0] : undefined
  }

  return (
    <div className="space-y-4" data-testid="ci-connections">
      {error ? (
        <ErrorState
          title={t('scans.ci.trust.configs', 'CI trust configurations')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : configs.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title={t('scans.ci.connections.emptyTitle', 'No CI provider connected yet')}
          description={
            canWrite
              ? t(
                  'scans.ci.connections.empty',
                  'Connect a CI provider to let its jobs send results with their own identity. No secret goes into CI.'
                )
              : t('scans.ci.setup.askAdmin', 'Ask an administrator to connect a pipeline.')
          }
        />
      ) : (
        <>
          <ConnectionsStatus
            configs={configs}
            refused={canWrite ? recent.length : 0}
            onSeeWhy={() => setRefusedParam('1')}
          />
          <ul className="divide-y rounded-lg border" data-testid="ci-trust-list">
            {configs.map((c) => (
              <ConnectionRow
                key={c.id}
                config={c}
                refused={canWrite ? recentRefusals(refusalsOf(c, refusedList), now).length : 0}
                onOpen={() => openConfig(c)}
              />
            ))}
          </ul>
        </>
      )}
      <OrganizationRules canWrite={canWrite} />
      {open && (
        <TrustSheet
          key={open.id}
          config={open}
          canWrite={canWrite}
          refusals={refusalsOf(open, refusedList)}
          tab={sheetTab}
          onTab={(v) => {
            if (v !== 'rules') setFix(null)
            setSheetTab(v)
          }}
          fix={fix}
          onFix={(f) => {
            setFix(f)
            setSheetTab('rules')
          }}
          onClose={() => {
            setFix(null)
            setSheetTab('health')
            setOpenId('')
          }}
          onChanged={() => void mutate()}
        />
      )}
      {canWrite && (
        <RefusedSheet
          open={!!refusedParam}
          onClose={() => setRefusedParam('')}
          onFix={(r, f) => {
            const c = targetOf(r)
            if (c) openConfig(c, 'rules', f)
          }}
          canFix={(r) => !!targetOf(r)}
        />
      )}
    </div>
  )
}

/** One line: is CI working, when did a job last get in, and how many were refused. */
function ConnectionsStatus({
  configs,
  refused,
  onSeeWhy,
}: {
  configs: CITrustConfig[]
  refused: number
  onSeeWhy: () => void
}) {
  const { t } = useTranslation()
  const working = configs.filter(isWorking).length
  const last = lastAccepted(configs)
  const ok = working > 0 && refused === 0
  const Icon = ok ? CheckCircle2 : AlertTriangle
  return (
    <p
      className="flex flex-wrap items-center gap-x-1 gap-y-1 text-sm"
      data-testid="ci-connections-status"
    >
      <Icon className={cn('size-4 shrink-0', ok ? 'text-success' : 'text-warning')} aria-hidden />
      <span className="font-medium">
        {working === 0
          ? t('scans.ci.status.noneWorking', 'No connection has let a job in yet')
          : t(
              working === 1 ? 'scans.ci.status.working.one' : 'scans.ci.status.working.other',
              working === 1 ? '1 connection working' : '{count} connections working',
              { count: working }
            )}
      </span>
      {last && (
        <span className="text-muted-foreground">
          {t('scans.ci.status.lastJob', ', last accepted job')} <RelativeTime date={last} />
        </span>
      )}
      {refused > 0 && (
        <>
          <span className="text-muted-foreground">,</span>
          <Button
            type="button"
            variant="link"
            size="sm"
            onClick={onSeeWhy}
            data-testid="ci-connections-see-why"
          >
            {t(
              refused === 1 ? 'scans.ci.status.refused.one' : 'scans.ci.status.refused.other',
              refused === 1 ? '1 job refused: see why' : '{count} jobs refused: see why',
              { count: refused }
            )}
          </Button>
        </>
      )}
    </p>
  )
}

/** A configuration as one line; the whole line opens its sheet. */
function ConnectionRow({
  config: c,
  refused,
  onOpen,
}: {
  config: CITrustConfig
  refused: number
  onOpen: () => void
}) {
  const { t } = useTranslation()
  const summary = rulesSummary(c, t)
  return (
    <li data-testid="ci-trust-row">
      <button
        type="button"
        onClick={onOpen}
        className="flex w-full flex-col gap-1 p-3 text-left hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none sm:flex-row sm:items-center sm:justify-between sm:gap-4"
        aria-label={t('scans.ci.connections.open', 'Open {name}', { name: c.name ?? '' })}
      >
        <span className="min-w-0 space-y-0.5">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground" aria-hidden>
              <ProviderIcon provider={c.provider ?? ''} />
            </span>
            <span className="break-words font-medium">{c.name}</span>
            {c.enabled === false && (
              <Badge variant="secondary">{t('scans.ci.disabled', 'Disabled')}</Badge>
            )}
            {c.rules?.allow_fork_pull_requests && (
              <Badge variant="destructive">
                {t('scans.ci.trust.forkBadge', 'Fork pull requests')}
              </Badge>
            )}
          </span>
          <span className="block truncate text-sm text-muted-foreground">
            {PROVIDER_LABEL[c.provider ?? ''] ?? c.provider}
            {summary ? `, ${summary}` : ''}
          </span>
        </span>
        <span
          className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground"
          data-testid="ci-trust-health"
        >
          <span>
            {c.last_used_at ? (
              <>
                {t('scans.ci.health.lastAccepted', 'Last accepted job')}{' '}
                <RelativeTime date={c.last_used_at} />
              </>
            ) : (
              t('scans.ci.health.noneAccepted', 'No job accepted yet')
            )}
          </span>
          {refused > 0 && (
            <span className="font-medium text-warning">
              {t('scans.ci.health.refusedCount', '{count} refused', { count: refused })}
            </span>
          )}
          <ChevronRight className="size-4" aria-hidden />
        </span>
      </button>
    </li>
  )
}

/** Organization-wide CI rules, folded: changed once, rarely again. */
function OrganizationRules({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const { data } = useCISettings()
  const [open, setOpen] = useState(false)
  const required = !!data?.require_oidc
  return (
    <Collapsible open={open} onOpenChange={setOpen} data-testid="ci-org-rules">
      <CollapsibleTrigger asChild>
        <Button type="button" variant="ghost" size="sm" aria-expanded={open}>
          <ChevronDown
            className={open ? 'rotate-180 transition-transform' : 'transition-transform'}
            aria-hidden
          />
          {t('scans.ci.orgRules.title', 'Organization rules')}
          {data && (
            <span
              className={cn('font-normal', required ? 'text-muted-foreground' : 'text-warning')}
            >
              {required
                ? t('scans.ci.orgRules.oidcOn', '(Require OIDC for CI results: on)')
                : t('scans.ci.orgRules.oidcOff', '(Require OIDC for CI results: off)')}
            </span>
          )}
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent className="pt-2">
        <CIRequireOIDC canWrite={canWrite} />
      </CollapsibleContent>
    </Collapsible>
  )
}

/** One configuration in a sheet: health, rules, scope entries and snippet. */
function TrustSheet({
  config,
  canWrite,
  refusals,
  tab,
  onTab,
  fix,
  onFix,
  onClose,
  onChanged,
}: {
  config: CITrustConfig
  canWrite: boolean
  refusals: CITokenRefusal[]
  tab: TrustSheetTab
  onTab: (tab: TrustSheetTab) => void
  fix: RefusalFix | null
  onFix: (fix: RefusalFix) => void
  onClose: () => void
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const [deleting, setDeleting] = useState(false)
  const { trigger: remove } = useDeleteTrustConfig()
  const tabs: { value: TrustSheetTab; label: string }[] = [
    { value: 'health', label: t('scans.ci.sheet.health', 'Health') },
    { value: 'rules', label: t('scans.ci.sheet.rules', 'Rules') },
    ...(manageScopeSupported(config.provider)
      ? [{ value: 'scope' as const, label: t('scans.ci.sheet.scope', 'Scope') }]
      : []),
    { value: 'snippet', label: t('scans.ci.trust.snippet', 'Pipeline snippet') },
  ]
  const shown = tabs.some((x) => x.value === tab) ? tab : 'health'
  return (
    <DetailSheet
      open
      onOpenChange={(o) => !o && onClose()}
      panel={shown}
      header={
        <DetailHeader
          title={config.name ?? ''}
          badges={
            config.enabled === false ? (
              <Badge variant="secondary">{t('scans.ci.disabled', 'Disabled')}</Badge>
            ) : undefined
          }
          meta={[PROVIDER_LABEL[config.provider ?? ''] ?? config.provider ?? '']}
          onClose={onClose}
          menu={
            canWrite
              ? [
                  {
                    label: t('scans.ci.trust.deleteLabel', 'Delete {name}', {
                      name: config.name ?? '',
                    }),
                    icon: Trash2,
                    destructive: true,
                    onSelect: () => setDeleting(true),
                  },
                ]
              : undefined
          }
        />
      }
      tabs={<DetailTabs tabs={tabs} value={shown} onValueChange={onTab} />}
    >
      {shown === 'health' ? (
        <HealthPanel config={config} refusals={refusals} onFix={canWrite ? onFix : undefined} />
      ) : shown === 'rules' ? (
        canWrite ? (
          <TrustConfigForm
            key={fix ? `${fix.kind}:${'value' in fix ? fix.value : ''}` : 'rules'}
            inline
            config={config}
            prefill={fix ?? undefined}
            onClose={() => onTab('health')}
            onSaved={() => {
              onChanged()
              onTab('health')
            }}
          />
        ) : (
          <p className="text-sm text-muted-foreground">
            {rulesSummary(config, t) || t('scans.ci.sheet.noRules', 'No rule beyond the provider.')}
          </p>
        )
      ) : shown === 'scope' ? (
        <div className="text-sm">
          <CITrustScopeEntries config={config} onChanged={onChanged} />
        </div>
      ) : (
        <SnippetPanel config={config} />
      )}
      <ConfirmDialog
        open={deleting}
        onOpenChange={(o) => !o && setDeleting(false)}
        title={t('confirm.ciTrust.deleteTitle', 'Delete the CI trust "{name}"?', {
          name: config.name ?? '',
        })}
        desc={t(
          'confirm.ciTrust.deleteDesc',
          'Pipelines it admits can no longer send results. Tokens already issued expire within 15 minutes. The repository scope entries it added are removed. This cannot be undone.'
        )}
        confirmText={t('confirm.ciTrust.deleteBtn')}
        destructive
        typeToConfirm={confirmName(config.name, config.id ?? '')}
        handleConfirm={() => {
          setDeleting(false)
          if (!config.id) return
          remove(config.id)
            .then(() => {
              toast.success(t('scans.ci.trust.deleted', 'CI trust deleted'))
              onClose()
              onChanged()
            })
            .catch((e: unknown) => toast.error(getErrorMessage(e)))
        }}
      />
    </DetailSheet>
  )
}

/** Last accepted job, the legacy-audience note, and refused jobs with their fixes. */
function HealthPanel({
  config,
  refusals,
  onFix,
}: {
  config: CITrustConfig
  refusals: CITokenRefusal[]
  onFix?: (fix: RefusalFix) => void
}) {
  const { t, locale } = useTranslation()
  return (
    <div className="space-y-4">
      <p className="text-sm" data-testid="ci-sheet-last-accepted">
        {config.last_used_at ? (
          <>
            {t('scans.ci.health.lastAccepted', 'Last accepted job')}{' '}
            <RelativeTime date={config.last_used_at} />
          </>
        ) : (
          t('scans.ci.health.noneAccepted', 'No job accepted yet')
        )}
      </p>
      {config.legacy_audience && config.legacy_audience_until && (
        <p className="break-words text-sm text-warning" data-testid="ci-legacy-audience">
          {t(
            'scans.ci.trust.legacyAudience',
            'Pipelines that existed before may still use the old audience {value} until {until}, until they use the new one once. Update their pipeline to the current snippet.',
            {
              value: config.legacy_audience,
              until: formatLocalized(config.legacy_audience_until, locale),
            }
          )}
        </p>
      )}
      {refusals.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t('scans.ci.sheet.noRefusals', 'No job of this connection was refused recently.')}
        </p>
      ) : (
        <div className="space-y-2">
          <h3 className="text-sm font-medium">{t('scans.ci.sheet.refusedJobs', 'Refused jobs')}</h3>
          <p className="text-sm text-muted-foreground">
            {t(
              'scans.ci.health.description',
              'Each job with the rule that refused it. A fix opens the configuration with the change filled in; nothing changes until you save.'
            )}
          </p>
          <ul className="divide-y rounded-lg border" data-testid="ci-health-refusals">
            {refusals.map((r, i) => (
              <li key={`${r.at}-${i}`} className="p-3">
                <RefusalDetail refusal={r} onFix={onFix} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

/** Every recent refused job (the status line's "see why"), each with its fix. */
function RefusedSheet({
  open,
  onClose,
  onFix,
  canFix,
}: {
  open: boolean
  onClose: () => void
  onFix: (refusal: CITokenRefusal, fix: RefusalFix) => void
  canFix: (refusal: CITokenRefusal) => boolean
}) {
  const { t } = useTranslation()
  return (
    <DetailSheet
      open={open}
      onOpenChange={(o) => !o && onClose()}
      header={
        <DetailHeader
          title={t('scans.ci.refusals.title', 'Recent refused pipelines')}
          onClose={onClose}
        />
      }
    >
      {open && <CITrustRefusals canWrite bare onFix={onFix} canFix={canFix} />}
    </DetailSheet>
  )
}
