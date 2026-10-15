'use client'

/**
 * CI trust and gate settings (api RFC-051):
 *   - trust configurations: which CI pipelines (GitHub Actions, GitLab CI,
 *     Azure Pipelines, Bitbucket Pipelines, CircleCI, Jenkins) may exchange
 *     their OIDC token for a short-lived upload token;
 *   - gate policy: what fails a pipeline (secrets always fail, accepted risk
 *     is always honored);
 *   - break-glass: let one commit pass for a limited time, audited.
 * Writes need scans:ci:write / scans:ci:override (owners and admins); the API
 * is the authority, the page only hides what the caller cannot do.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Check, Copy, KeyRound, Lock, Plus, ShieldAlert, Trash2 } from 'lucide-react'
import Link from '@/components/link'
import { PageHeader, EmptyState, ErrorState, GatedButton } from '@/features/shared'
import { CIRequireOIDC } from './ci-require-oidc'
import { CIPRFeedback } from './ci-pr-feedback'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  useDeleteGatePolicy,
  useDeleteTrustConfig,
  useGateOverrides,
  useGatePolicies,
  useRevokeGateOverride,
  useSaveGatePolicy,
  useSaveTrustConfig,
  useTrustConfigs,
} from '../api/use-ci'
import {
  CI_PROVIDERS,
  PROVIDER_LABEL,
  PROVIDER_TRAITS,
  SEVERITY_OPTIONS,
  defaultAudience,
  issuerFor,
  joinList,
  organizationFromIssuer,
  parseList,
  shortSHA,
  snippetFor,
} from '../lib/ci'
import { CITrustPreview } from './ci-trust-preview'
import { CIOverrideDialog } from './ci-override-dialog'
import { CITrustRefusals } from './ci-refusals'
import { CISetupEntry } from './ci-setup-wizard'
import { CITrustScopeEntries, manageScopeSupported } from './ci-trust-scope'
import type { CIGatePolicy, CIProvider, CITrustConfig, CITrustConfigRequest } from '../types'
import {
  GATE_FIELDS,
  GATE_FIELD_LABEL,
  MAX_REASON,
  validReason,
  type GateField,
} from '../lib/gate-settings'

const NO_WRITE = 'Only owners and administrators can change CI trust and the gate'

type TFn = ReturnType<typeof useTranslation>['t']

/**
 * Trust, gate policy and break-glass. `embedded` drops the page header (the
 * CI/CD integration page shows these as its Trust and gate tab).
 */
const SETUP_SECTIONS = ['trust', 'gate', 'break-glass', 'feedback'] as const
type SetupSection = (typeof SETUP_SECTIONS)[number]

/** The setup section a URL asks for; anything unknown is Trust. */
export function setupSection(raw: string): SetupSection {
  return (SETUP_SECTIONS as readonly string[]).includes(raw) ? (raw as SetupSection) : 'trust'
}

export function CITrustSettings({ embedded = false }: { embedded?: boolean } = {}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.CIWrite)
  const canOverride = can(Permission.CIOverride)
  // The open section lives in the URL (?section=), so a link (the GitHub App
  // callback, an alert, the docs) can land on it.
  const [sectionParam, setSectionParam] = useUrlFilter('section', 'trust')
  const section = setupSection(sectionParam)
  const setSection = (v: string) => setSectionParam(setupSection(v))
  return (
    <div className="space-y-4">
      {!embedded && (
        <PageHeader
          title={t('scans.ci.title', 'CI/CD integration')}
          description={t(
            'scans.ci.trustDescription',
            'Which CI jobs may send results with their own identity, and what fails a pipeline.'
          )}
        />
      )}
      <CIRequireOIDC canWrite={canWrite} />
      <Tabs value={section} onValueChange={setSection}>
        <TabsList>
          <TabsTrigger value="trust">{t('scans.ci.trust.tab', 'Trust')}</TabsTrigger>
          <TabsTrigger value="gate">{t('scans.ci.gatePolicy.tab', 'Gate policy')}</TabsTrigger>
          <TabsTrigger value="break-glass">
            {t('scans.ci.breakGlass.tab', 'Break-glass')}
          </TabsTrigger>
          <TabsTrigger value="feedback">
            {t('scans.ci.feedback.tab', 'Pull request feedback')}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="trust" className="mt-4">
          <TrustConfigsSection canWrite={canWrite} />
        </TabsContent>
        <TabsContent value="gate" className="mt-4">
          <GatePolicySection canWrite={can(Permission.CIPolicy)} />
        </TabsContent>
        <TabsContent value="break-glass" className="mt-4">
          <OverridesSection canOverride={canOverride} />
        </TabsContent>
        <TabsContent value="feedback" className="mt-4">
          <CIPRFeedback canWrite={canWrite} />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// ─────────────────────────────────────────────────────────── trust ───

function rulesSummary(c: CITrustConfig, t: TFn): string {
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
  return parts.join(' · ')
}

function TrustConfigsSection({ canWrite }: { canWrite: boolean }) {
  const { data, error, isLoading, mutate } = useTrustConfigs()
  const { trigger: remove } = useDeleteTrustConfig()
  const [editing, setEditing] = useState<CITrustConfig | 'new' | null>(null)
  const [snippetOf, setSnippetOf] = useState<CITrustConfig | null>(null)
  const [deleting, setDeleting] = useState<CITrustConfig | null>(null)
  const { t } = useTranslation()
  const configs = data?.data ?? []

  if (error)
    return (
      <ErrorState
        title={t('scans.ci.trust.configs', 'CI trust configurations')}
        error={error}
        onRetry={() => mutate()}
      />
    )
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-end gap-2">
        {canWrite && <CISetupEntry canWrite />}
        <GatedButton
          allowed={canWrite}
          reason={t('scans.ci.noWrite', NO_WRITE)}
          size="sm"
          variant={canWrite ? 'outline' : 'default'}
          onClick={() => setEditing('new')}
        >
          <Plus className="size-4" aria-hidden /> {t('scans.ci.trust.add', 'Add trust')}
        </GatedButton>
      </div>
      {isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : configs.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title={t('scans.ci.noTrustTitle', 'No CI trust yet')}
          description={t(
            'scans.ci.noTrust',
            'Name the organizations or repositories whose pipelines may send results.'
          )}
        />
      ) : (
        configs.map((c) => (
          <Card key={c.id}>
            <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
              <div className="min-w-0 space-y-1">
                <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                  {c.name}
                  <Badge variant="outline">{PROVIDER_LABEL[c.provider ?? ''] ?? c.provider}</Badge>
                  {!c.enabled && (
                    <Badge variant="secondary">{t('scans.ci.disabled', 'Disabled')}</Badge>
                  )}
                  {c.rules?.allow_fork_pull_requests && (
                    <Badge variant="destructive">
                      {t('scans.ci.trust.forkBadge', 'Fork pull requests')}
                    </Badge>
                  )}
                </CardTitle>
                <CardDescription className="break-all">{rulesSummary(c, t)}</CardDescription>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setSnippetOf(c)}>
                  {t('scans.ci.trust.snippet', 'Pipeline snippet')}
                </Button>
                <GatedButton
                  allowed={canWrite}
                  reason={t('scans.ci.noWrite', NO_WRITE)}
                  variant="outline"
                  size="sm"
                  onClick={() => setEditing(c)}
                >
                  {t('scans.ci.edit', 'Edit')}
                </GatedButton>
                <GatedButton
                  allowed={canWrite}
                  reason={t('scans.ci.noWrite', NO_WRITE)}
                  variant="ghost"
                  size="sm"
                  aria-label={t('scans.ci.trust.deleteLabel', 'Delete {name}', {
                    name: c.name ?? '',
                  })}
                  onClick={() => setDeleting(c)}
                >
                  <Trash2 className="size-4" aria-hidden />
                </GatedButton>
              </div>
            </CardHeader>
            <CardContent className="grid gap-1 text-sm text-muted-foreground sm:grid-cols-2">
              <span className="break-all">
                {t('scans.ci.trust.issuerValue', 'Issuer: {value}', { value: c.issuer ?? '' })}
              </span>
              <span className="break-all">
                {t('scans.ci.trust.audienceValue', 'Audience: {value}', {
                  value: c.audience ?? '',
                })}
              </span>
              {c.legacy_audience && c.legacy_audience_until && (
                <span
                  className="break-all text-warning sm:col-span-2"
                  data-testid="ci-legacy-audience"
                >
                  {t(
                    'scans.ci.trust.legacyAudience',
                    'Pipelines that existed before may still use the old audience {value} until {until}, until they use the new one once. Update their pipeline to the current snippet.',
                    {
                      value: c.legacy_audience,
                      until: new Date(c.legacy_audience_until).toLocaleDateString(),
                    }
                  )}
                </span>
              )}
              <span>
                {t('scans.ci.trust.defaultBranchValue', 'Default branch: {value}', {
                  value: c.default_branch ?? '',
                })}
              </span>
              <span>
                {t('scans.ci.trust.lastUsedValue', 'Last used: {value}', {
                  value: c.last_used_at
                    ? new Date(c.last_used_at).toLocaleString()
                    : t('scans.ci.trust.never', 'never'),
                })}
              </span>
              <CITrustScopeEntries config={c} onChanged={() => void mutate()} />
            </CardContent>
          </Card>
        ))
      )}
      {editing && (
        <TrustConfigDialog
          config={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(c) => {
            setEditing(null)
            void mutate()
            if (editing === 'new') setSnippetOf(c)
          }}
        />
      )}
      <CITrustRefusals canWrite={canWrite} />
      {snippetOf && <SnippetDialog config={snippetOf} onClose={() => setSnippetOf(null)} />}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('confirm.ciTrust.deleteTitle', 'Delete the CI trust "{name}"?', {
          name: deleting?.name ?? '',
        })}
        desc={t(
          'confirm.ciTrust.deleteDesc',
          'Pipelines it admits can no longer send results. Tokens already issued expire within 15 minutes. The repository scope entries it added are removed. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        handleConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target?.id) return
          remove(target.id)
            .then(() => {
              toast.success(t('scans.ci.trust.deleted', 'CI trust deleted'))
              void mutate()
            })
            .catch((e: unknown) => toast.error(getErrorMessage(e)))
        }}
      />
    </div>
  )
}

function TrustConfigDialog({
  config,
  onClose,
  onSaved,
}: {
  config: CITrustConfig | null
  onClose: () => void
  onSaved: (c: CITrustConfig) => void
}) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const { trigger: save, isMutating } = useSaveTrustConfig()
  const initialProvider = (config?.provider as CIProvider) ?? 'github'
  const [name, setName] = useState(config?.name ?? '')
  const [provider, setProvider] = useState<CIProvider>(initialProvider)
  // The issuer as the administrator enters it: an organization id
  // (Azure, CircleCI), a workspace (Bitbucket) or a URL (GitLab, Jenkins).
  const [organization, setOrganization] = useState(
    organizationFromIssuer(initialProvider, config?.issuer)
  )
  const [workspaceUUID, setWorkspaceUUID] = useState(config?.rules?.workspace_uuid ?? '')
  const [audience, setAudience] = useState(config?.audience ?? '')
  const [defaultBranch, setDefaultBranch] = useState(config?.default_branch ?? 'main')
  const [owners, setOwners] = useState(joinList(config?.rules?.owners))
  const [repositories, setRepositories] = useState(joinList(config?.rules?.repositories))
  const [refs, setRefs] = useState(joinList(config?.rules?.refs))
  const [environments, setEnvironments] = useState(joinList(config?.rules?.environments))
  const [events, setEvents] = useState(joinList(config?.rules?.events))
  const [workflowRefs, setWorkflowRefs] = useState(joinList(config?.rules?.workflow_refs))
  const [allowForks, setAllowForks] = useState(!!config?.rules?.allow_fork_pull_requests)
  const [protectedRef, setProtectedRef] = useState(!!config?.rules?.require_protected_ref)
  const [enabled, setEnabled] = useState(config?.enabled ?? true)
  const { can } = usePermissions()
  const canScope = can(Permission.ScopeWrite)
  // On by default for someone who may change scope; the API refuses it for
  // anyone else.
  const [manageScope, setManageScope] = useState(config?.manage_scope ?? canScope)
  const traits = PROVIDER_TRAITS[provider]

  const chooseProvider = (p: CIProvider) => {
    setProvider(p)
    setOrganization('')
    setWorkspaceUUID('')
    setAudience('')
    if (!PROVIDER_TRAITS[p].events) setEvents('')
    if (!PROVIDER_TRAITS[p].environments) setEnvironments('')
    if (PROVIDER_TRAITS[p].protectedRef === 'none') setProtectedRef(false)
    if (!PROVIDER_TRAITS[p].workflowRefs) setWorkflowRefs('')
  }

  const body = (): CITrustConfigRequest => ({
    name: name.trim() || 'preview',
    provider,
    issuer:
      provider === 'github'
        ? organization.trim() || undefined
        : traits.issuerInput === 'fixed'
          ? undefined
          : issuerFor(provider, organization),
    audience: traits.fixedAudience ? undefined : audience.trim() || undefined,
    default_branch: defaultBranch.trim() || undefined,
    enabled,
    manage_scope: manageScopeSupported(provider) && canScope ? manageScope : undefined,
    rules: {
      owners: parseList(owners),
      repositories: parseList(repositories),
      refs: parseList(refs),
      environments: traits.environments ? parseList(environments) : [],
      events: traits.events ? parseList(events) : [],
      workflow_refs: traits.workflowRefs ? parseList(workflowRefs) : [],
      allow_fork_pull_requests: allowForks,
      require_protected_ref: traits.protectedRef === 'none' ? false : protectedRef,
      workspace_uuid: provider === 'bitbucket' ? workspaceUUID.trim() || undefined : undefined,
    },
  })

  const noScope = parseList(owners).length === 0 && parseList(repositories).length === 0
  const needsIssuer =
    traits.issuerInput !== 'fixed' && provider !== 'gitlab' && !organization.trim()
  const submit = async () => {
    if (!name.trim()) return toast.error(t('scans.ci.trust.nameRequired', 'Name is required'))
    if (noScope)
      return toast.error(t('scans.ci.trust.scopeRequired', 'Name at least one owner or repository'))
    try {
      const saved = await save({ id: config?.id, body: body() })
      toast.success(
        config
          ? t('scans.ci.trust.updated', 'CI trust updated')
          : t('scans.ci.trust.added', 'CI trust added')
      )
      onSaved(saved)
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  const tenantAudience = defaultAudience(currentTenant?.id ?? '<tenant id>')
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {config
              ? t('scans.ci.trust.editTitle', 'Edit CI trust')
              : t('scans.ci.trust.addTitle', 'Add CI trust')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'scans.ci.trust.dialogDescription',
              'A pipeline is admitted when every rule you fill in matches its token. Lists are comma separated; patterns use * for one path segment and ** for any depth.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-3">
            <Field label={t('scans.ci.trust.name', 'Name')} id="ci-name">
              <Input id="ci-name" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label={t('scans.ci.col.provider', 'Provider')} id="ci-provider">
              <Select
                value={provider}
                onValueChange={(v) => chooseProvider(v as CIProvider)}
                disabled={!!config}
              >
                <SelectTrigger id="ci-provider">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CI_PROVIDERS.map((p) => (
                    <SelectItem key={p} value={p}>
                      {PROVIDER_LABEL[p]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            {provider === 'github' && (
              <Field
                label={t('scans.ci.trust.githubIssuer', 'GitHub Enterprise issuer (optional)')}
                id="ci-issuer"
                hint={t(
                  'scans.ci.trust.githubIssuerHint',
                  'Leave empty for github.com. GitHub Enterprise Server: https://<host>/_services/token. An enterprise with a customized issuer: https://token.actions.githubusercontent.com/<enterprise>.'
                )}
              >
                <Input
                  id="ci-issuer"
                  placeholder="https://token.actions.githubusercontent.com"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                />
              </Field>
            )}
            {provider === 'gitlab' && (
              <Field
                label={t('scans.ci.trust.gitlabIssuer', 'GitLab URL (issuer)')}
                id="ci-issuer"
                hint={t('scans.ci.trust.gitlabIssuerHint', 'Leave empty for gitlab.com.')}
              >
                <Input
                  id="ci-issuer"
                  placeholder="https://gitlab.com"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                />
              </Field>
            )}
            {provider === 'jenkins' && (
              <Field
                label={t('scans.ci.trust.issuer', 'Issuer')}
                id="ci-issuer"
                hint={t(
                  'scans.ci.trust.jenkinsIssuerHint',
                  "The OpenID Connect Provider plugin's issuer: <Jenkins URL>/oidc, a folder's issuer, or the credential's issuer URI when the platform cannot reach the controller."
                )}
              >
                <Input
                  id="ci-issuer"
                  placeholder="https://jenkins.example.com/oidc"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                />
              </Field>
            )}
            {traits.issuerInput === 'organization_id' && (
              <Field
                label={t('scans.ci.trust.orgId', 'Organization id')}
                id="ci-org"
                hint={
                  provider === 'azure_devops'
                    ? t(
                        'scans.ci.trust.azureOrgHint',
                        'The Azure DevOps organization id (a UUID), the org_id of its tokens.'
                      )
                    : t(
                        'scans.ci.trust.circleciOrgHint',
                        'The CircleCI organization id (Organization settings > Overview).'
                      )
                }
              >
                <Input
                  id="ci-org"
                  placeholder="00000000-0000-0000-0000-000000000000"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                />
              </Field>
            )}
            {provider === 'bitbucket' && (
              <>
                <Field
                  label={t('scans.ci.trust.workspace', 'Workspace')}
                  id="ci-org"
                  hint={t('scans.ci.trust.workspaceHint', 'As in bitbucket.org/<workspace>.')}
                >
                  <Input
                    id="ci-org"
                    placeholder="acme"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                  />
                </Field>
                <Field
                  label={t('scans.ci.trust.workspaceUuid', 'Workspace UUID')}
                  id="ci-ws-uuid"
                  hint={t(
                    'scans.ci.trust.workspaceUuidHint',
                    'Required: a renamed workspace gives up its name, never its UUID.'
                  )}
                >
                  <Input
                    id="ci-ws-uuid"
                    placeholder="{00000000-0000-0000-0000-000000000000}"
                    value={workspaceUUID}
                    onChange={(e) => setWorkspaceUUID(e.target.value)}
                  />
                </Field>
              </>
            )}
            <Field
              label={t('scans.ci.trust.owners', 'Owners')}
              id="ci-owners"
              hint={
                provider === 'gitlab'
                  ? t('scans.ci.trust.ownersGitlab', 'Top-level groups.')
                  : provider === 'bitbucket'
                    ? t('scans.ci.trust.ownersBitbucket', 'The workspace.')
                    : t(
                        'scans.ci.trust.ownersHint',
                        'Organizations or users that own the repositories.'
                      )
              }
            >
              <Input
                id="ci-owners"
                placeholder="acme"
                value={owners}
                onChange={(e) => setOwners(e.target.value)}
              />
            </Field>
            <Field
              label={t('scans.ci.trust.repositories', 'Repositories')}
              id="ci-repos"
              hint={
                traits.repositoriesById
                  ? t(
                      'scans.ci.trust.repositoriesById',
                      'Repository UUIDs: the token signs the id, never the name.'
                    )
                  : t('scans.ci.trust.repositoriesHint', 'owner/name, owner/* or owner/**.')
              }
            >
              <Input
                id="ci-repos"
                placeholder={
                  traits.repositoriesById
                    ? t('scans.ci.trust.repositoryUuidPlaceholder', '{repository uuid}')
                    : 'acme/api, acme/web'
                }
                value={repositories}
                onChange={(e) => setRepositories(e.target.value)}
              />
            </Field>
            <Field
              label={t('scans.ci.trust.refs', 'Branches and tags')}
              id="ci-refs"
              hint={t(
                'scans.ci.trust.refsHint',
                'Empty admits every ref. For a pull request, its source branch.'
              )}
            >
              <Input
                id="ci-refs"
                placeholder="main, release/*"
                value={refs}
                onChange={(e) => setRefs(e.target.value)}
              />
            </Field>
            {traits.environments && (
              <Field
                label={t('scans.ci.trust.environments', 'Environments')}
                id="ci-envs"
                hint={
                  provider === 'bitbucket'
                    ? t(
                        'scans.ci.trust.environmentsBitbucket',
                        'Optional: deployment environment UUIDs.'
                      )
                    : t(
                        'scans.ci.trust.environmentsHint',
                        'Optional: require a deployment environment.'
                      )
                }
              >
                <Input
                  id="ci-envs"
                  value={environments}
                  onChange={(e) => setEnvironments(e.target.value)}
                />
              </Field>
            )}
            {traits.events && (
              <Field
                label={t('scans.ci.trust.events', 'Events')}
                id="ci-events"
                hint={t(
                  'scans.ci.trust.eventsHint',
                  'Optional: push, pull_request, merge_request_event, schedule...'
                )}
              >
                <Input id="ci-events" value={events} onChange={(e) => setEvents(e.target.value)} />
              </Field>
            )}
            {traits.workflowRefs && (
              <Field
                label={t('scans.ci.trust.workflowRefs', 'Pipeline definitions')}
                id="ci-workflow-refs"
                hint={
                  provider === 'gitlab'
                    ? t(
                        'scans.ci.trust.workflowRefsGitlab',
                        'Optional: admit only pipelines that use this configuration, as <host>/<project>//<file>@<ref> (the ci_config_ref_uri claim). A project that edits its own configuration is refused.'
                      )
                    : t(
                        'scans.ci.trust.workflowRefsHint',
                        'Optional: admit only jobs that run your central workflow, as owner/repo/.github/workflows/<file>@<ref> (the job_workflow_ref claim; * in the ref). A pull request that edits or adds a workflow is refused.'
                      )
                }
              >
                <Input
                  id="ci-workflow-refs"
                  placeholder={
                    provider === 'gitlab'
                      ? 'gitlab.com/acme/ci//scan.yml@refs/heads/main'
                      : 'acme/security/.github/workflows/scan.yml@refs/heads/main'
                  }
                  value={workflowRefs}
                  onChange={(e) => setWorkflowRefs(e.target.value)}
                />
              </Field>
            )}
            <Field
              label={t('scans.ci.col.defaultBranch', 'Default branch')}
              id="ci-default"
              hint={t(
                'scans.ci.trust.defaultBranchHint',
                "The baseline when the platform does not know the repository's default branch yet."
              )}
            >
              <Input
                id="ci-default"
                value={defaultBranch}
                onChange={(e) => setDefaultBranch(e.target.value)}
              />
            </Field>
            {traits.fixedAudience ? (
              <p className="text-xs text-muted-foreground" data-testid="ci-fixed-audience">
                {t(
                  'scans.ci.trust.fixedAudience',
                  'Audience: {audience}, the only one Azure Pipelines issues. Tokens are pinned to this organization id and accepted once.',
                  { audience: traits.fixedAudience }
                )}
              </p>
            ) : (
              <Field
                label={t('scans.ci.trust.audience', 'Audience')}
                id="ci-aud"
                hint={
                  traits.tenantAudience
                    ? t(
                        'scans.ci.trust.audienceTenantHint',
                        'Default: {audience}. Must contain your organization id.',
                        { audience: tenantAudience }
                      )
                    : t('scans.ci.trust.audienceHint', 'Default: {audience}', {
                        audience: tenantAudience,
                      })
                }
              >
                <Input id="ci-aud" value={audience} onChange={(e) => setAudience(e.target.value)} />
              </Field>
            )}
            {traits.protectedRef !== 'none' && (
              <SwitchRow
                id="ci-protected"
                label={t('scans.ci.trust.protectedOnly', 'Protected branches and tags only')}
                checked={protectedRef}
                onChange={setProtectedRef}
              />
            )}
            {protectedRef && traits.protectedRef === 'environment' && (
              <p className="text-muted-foreground text-xs">
                {t(
                  'scans.ci.trust.protectedByEnvironment',
                  '{provider} tokens do not say whether a ref is protected. List the deployment environments above whose deployment branch rules admit only protected branches and tags; only jobs running in one of them are admitted.',
                  { provider: PROVIDER_LABEL[provider] }
                )}
              </p>
            )}
            <SwitchRow
              id="ci-forks"
              label={
                traits.pullRequestsAsForks
                  ? t('scans.ci.trust.admitPullRequests', 'Admit pull request builds')
                  : t('scans.ci.trust.admitForks', 'Admit fork pull requests')
              }
              checked={allowForks}
              onChange={setAllowForks}
            />
            {traits.pullRequestsAsForks && !allowForks && (
              <p className="text-muted-foreground text-xs">
                {t(
                  'scans.ci.trust.forksIndistinguishable',
                  "{provider} tokens cannot tell a fork's pull request from your own, so pull request builds are refused.",
                  { provider: PROVIDER_LABEL[provider] }
                )}
              </p>
            )}
            {allowForks && (
              <Alert variant="destructive">
                <ShieldAlert />
                <AlertTitle>
                  {t(
                    'scans.ci.trust.forkWarningTitle',
                    "Fork code would act with this repository's identity"
                  )}
                </AlertTitle>
                <AlertDescription>
                  {traits.pullRequestsAsForks
                    ? t(
                        'scans.ci.trust.forkWarningAll',
                        'Every pull request build is admitted, including builds of fork code. Turn this on only if the pipeline never builds fork pull requests.'
                      )
                    : t(
                        'scans.ci.trust.forkWarningEvents',
                        'Events such as pull_request_target run code from a fork. Leave this off unless the workflow never checks out fork code.'
                      )}
                </AlertDescription>
              </Alert>
            )}
            {manageScopeSupported(provider) && (
              <div className="space-y-1">
                <SwitchRow
                  id="ci-manage-scope"
                  label={t('scans.ci.trust.manageScope', 'Trust and add to scope')}
                  checked={manageScope}
                  onChange={setManageScope}
                  disabled={!canScope}
                />
                <p className="text-xs text-muted-foreground">
                  {canScope
                    ? t(
                        'scans.ci.trust.manageScopeHint',
                        "Each owner or repository becomes a repository scope entry (for example gitlab.com/your-group/*), kept in step with this trust and removed with it. The entries follow your organization's scope approval rules."
                      )
                    : t(
                        'scans.ci.trust.manageScopeNoPermission',
                        'Adding repositories to scope needs the scope write permission.'
                      )}
                </p>
              </div>
            )}
            <SwitchRow
              id="ci-enabled"
              label={t('scans.ci.enabled', 'Enabled')}
              checked={enabled}
              onChange={setEnabled}
            />
            {!needsIssuer && <CITrustPreview provider={provider} draft={body} />}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={isMutating || noScope || needsIssuer || !name.trim()}>
            {config ? t('common.save', 'Save') : t('scans.ci.add', 'Add')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function SnippetDialog({ config, onClose }: { config: CITrustConfig; onClose: () => void }) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const [copied, setCopied] = useState(false)
  const snippet = useMemo(
    () =>
      snippetFor((config.provider as CIProvider) ?? 'github', {
        apiUrl:
          typeof window === 'undefined' ? 'https://openctem.example.com' : window.location.origin,
        tenantId: currentTenant?.id ?? '',
        audience: config.audience ?? '',
      }),
    [config, currentTenant]
  )
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scans.ci.trust.snippet', 'Pipeline snippet')}</DialogTitle>
          <DialogDescription>
            {t(
              'scans.ci.trust.snippetDescription',
              'The job asks its CI provider for an OIDC token and exchanges it for a run token. Nothing secret goes into CI; the token is never printed. The job fails when the gate does.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          {!!config.rules?.workflow_refs?.length && (
            <p
              className="mb-2 text-sm text-muted-foreground"
              data-testid="ci-snippet-workflow-refs"
            >
              {t(
                'scans.ci.trust.snippetWorkflowRefs',
                'This trust admits only jobs that run {list}. Put these steps in that pipeline definition and call it from each repository; a job defined anywhere else is refused.',
                { list: joinList(config.rules.workflow_refs) }
              )}
            </p>
          )}
          <pre
            className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs"
            data-testid="ci-snippet"
          >
            {snippet}
          </pre>
        </DialogBody>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={async () => {
              await copyToClipboard(snippet)
              setCopied(true)
            }}
          >
            {copied ? (
              <Check className="size-4" aria-hidden />
            ) : (
              <Copy className="size-4" aria-hidden />
            )}
            {copied ? t('scans.ci.copied', 'Copied') : t('scans.ci.copy', 'Copy')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ──────────────────────────────────────────────────────────── gate ───

function policyScope(p: CIGatePolicy, t: TFn): string {
  if (p.scope_type === 'tenant') return t('scans.ci.gatePolicy.scopeOrg', 'Organization')
  if (p.scope_type === 'business_unit')
    return t('scans.ci.gatePolicy.scopeUnit', 'Business unit {id}', { id: p.scope_id ?? '' })
  return t('scans.ci.gatePolicy.scopeRepo', 'Repository {id}', { id: p.scope_id ?? '' })
}

function GatePolicySection({ canWrite }: { canWrite: boolean }) {
  const { data, error, isLoading, mutate } = useGatePolicies()
  const { trigger: remove } = useDeleteGatePolicy()
  const [editing, setEditing] = useState<CIGatePolicy | null>(null)
  const [adding, setAdding] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<CIGatePolicy | null>(null)
  const [deleteReason, setDeleteReason] = useState('')
  const { t } = useTranslation()
  const policies = data?.data ?? []
  const tenantPolicy = policies.find((p) => p.scope_type === 'tenant')
  const others = policies.filter((p) => p.scope_type !== 'tenant')

  if (error)
    return (
      <ErrorState
        title={t('scans.ci.gatePolicy.list', 'gate policies')}
        error={error}
        onRetry={() => mutate()}
      />
    )
  if (isLoading) return <Skeleton className="h-40 w-full" />
  const shown = tenantPolicy ?? data?.default
  return (
    <div className="space-y-4">
      <Alert>
        <ShieldAlert />
        <AlertTitle>{t('scans.ci.gatePolicy.alwaysOn', 'Always on')}</AlertTitle>
        <AlertDescription>
          {t(
            'scans.ci.gatePolicy.alwaysOnBody',
            'A committed secret always fails the pipeline. Accepted risk, false positives and suppressions are always honored while they apply. A scanner that fails to run fails the pipeline.'
          )}
        </AlertDescription>
      </Alert>
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-base">
              {t('scans.ci.gatePolicy.orgPolicy', 'Organization policy')}
            </CardTitle>
            <CardDescription>
              {tenantPolicy
                ? t(
                    'scans.ci.gatePolicy.orgApplies',
                    'Applies to every repository without its own policy.'
                  )
                : t(
                    'scans.ci.gatePolicy.builtIn',
                    'Built-in default: no organization policy is set.'
                  )}
            </CardDescription>
          </div>
          <GatedButton
            allowed={canWrite}
            reason={t('scans.ci.noWrite', NO_WRITE)}
            size="sm"
            variant="outline"
            onClick={() => setEditing(tenantPolicy ?? { scope_type: 'tenant' })}
          >
            {tenantPolicy ? t('scans.ci.edit', 'Edit') : t('scans.ci.gatePolicy.set', 'Set policy')}
          </GatedButton>
        </CardHeader>
        <CardContent className="text-sm">{shown ? <PolicySummary p={shown} /> : null}</CardContent>
      </Card>
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium">
          {t('scans.ci.gatePolicy.scoped', 'Business unit and repository policies')}
        </h2>
        <GatedButton
          allowed={canWrite}
          reason={t('scans.ci.noWrite', NO_WRITE)}
          size="sm"
          onClick={() => setAdding(true)}
        >
          <Plus className="size-4" aria-hidden /> {t('scans.ci.gatePolicy.add', 'Add policy')}
        </GatedButton>
      </div>
      {others.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t(
            'scans.ci.gatePolicy.none',
            "None. A repository uses its own policy, else the strictest of its business units', else the organization's."
          )}
        </p>
      ) : (
        others.map((p) => (
          <Card key={p.id}>
            <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
              <CardTitle className="break-all text-sm">{policyScope(p, t)}</CardTitle>
              <div className="flex gap-2">
                <GatedButton
                  allowed={canWrite}
                  reason={t('scans.ci.noWrite', NO_WRITE)}
                  variant="outline"
                  size="sm"
                  onClick={() => setEditing(p)}
                >
                  {t('scans.ci.edit', 'Edit')}
                </GatedButton>
                <GatedButton
                  allowed={canWrite}
                  reason={t('scans.ci.noWrite', NO_WRITE)}
                  variant="ghost"
                  size="sm"
                  aria-label={t('confirm.gatePolicy.deleteLabel', 'Delete the policy for {scope}', {
                    scope: policyScope(p, t),
                  })}
                  onClick={() => setPendingDelete(p)}
                >
                  <Trash2 className="size-4" aria-hidden />
                </GatedButton>
              </div>
            </CardHeader>
            <CardContent className="text-sm">
              <PolicySummary p={p} />
            </CardContent>
          </Card>
        ))
      )}
      {(editing || adding) && (
        <PolicyDialog
          policy={editing}
          overrideCounts={data?.override_counts ?? {}}
          onClose={() => {
            setEditing(null)
            setAdding(false)
          }}
          onSaved={() => {
            setEditing(null)
            setAdding(false)
            void mutate()
          }}
        />
      )}
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => {
          if (!o) {
            setPendingDelete(null)
            setDeleteReason('')
          }
        }}
        destructive
        disabled={deleteReason.trim() !== '' && !validReason(deleteReason)}
        title={t('confirm.gatePolicy.deleteTitle', 'Delete the gate policy for {scope}?', {
          scope: pendingDelete ? policyScope(pendingDelete, t) : '',
        })}
        desc={t(
          'confirm.gatePolicy.deleteDesc',
          'Pipelines in this scope fall back to the organization policy from their next run. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        handleConfirm={async () => {
          if (!pendingDelete) return
          try {
            await remove({ id: pendingDelete.id ?? '', reason: deleteReason })
            setPendingDelete(null)
            setDeleteReason('')
            void mutate()
          } catch (e) {
            toast.error(getErrorMessage(e))
          }
        }}
      >
        {pendingDelete && pendingDelete.scope_type !== 'tenant' && (
          <div className="space-y-1.5">
            <Label htmlFor="gate-policy-delete-reason">
              {t(
                'scans.ci.gatePolicy.deleteReason',
                'Reason (required when this loosens the gate)'
              )}
            </Label>
            <Textarea
              id="gate-policy-delete-reason"
              value={deleteReason}
              onChange={(e) => setDeleteReason(e.target.value)}
              maxLength={MAX_REASON}
              rows={2}
              aria-invalid={deleteReason.trim() !== '' && !validReason(deleteReason)}
            />
            <p className="text-xs text-muted-foreground">
              {t(
                'scans.ci.gatePolicy.deleteReasonHelp',
                '10 to 500 characters. If the policy this scope falls back to lets more findings pass, every administrator is told and you may be asked to confirm your identity.'
              )}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

function PolicySummary({ p }: { p: CIGatePolicy }) {
  const { t } = useTranslation()
  return (
    <ul className="grid gap-1 text-muted-foreground sm:grid-cols-2">
      <li>
        {p.mode === 'warn'
          ? t('scans.ci.gatePolicy.modeWarn', 'Mode: warn (report, never fail)')
          : t('scans.ci.gatePolicy.modeEnforce', 'Mode: enforce')}
      </li>
      <li>
        {p.fail_on_severity === 'none'
          ? t('scans.ci.gatePolicy.failsOnNone', 'Fails on: no severity')
          : t('scans.ci.gatePolicy.failsOn', 'Fails on: {severity} and above', {
              severity: p.fail_on_severity ?? '',
            })}
      </li>
      <li>
        {p.new_findings_only
          ? t('scans.ci.gatePolicy.newOnly', 'New findings only (compared with the default branch)')
          : t('scans.ci.gatePolicy.every', 'Every finding')}
      </li>
      <li>
        {p.fail_on_kev
          ? t('scans.ci.gatePolicy.kevFails', 'Known exploited (KEV): fails')
          : t('scans.ci.gatePolicy.kevNoFail', 'Known exploited (KEV): does not fail')}
      </li>
      {p.fixable_only && (
        <li>
          {t(
            'scans.ci.gatePolicy.fixableOnly',
            'Vulnerabilities without a fix: listed, not blocking (KEV still fails)'
          )}
        </li>
      )}
      {p.epss_threshold !== undefined && p.epss_threshold !== null && (
        <li>
          {t('scans.ci.gatePolicy.epssAtLeast', 'EPSS at least {value}', {
            value: p.epss_threshold,
          })}
        </li>
      )}
      {p.baseline_on_first_run && (
        <li>
          {typeof p.baseline_grace_days === 'number'
            ? t(
                'scans.ci.gatePolicy.baselineFirstRunGrace',
                'Baseline on first run; it blocks again after {count} days',
                { count: p.baseline_grace_days }
              )
            : t('scans.ci.gatePolicy.baselineFirstRun', 'Baseline on first run')}
        </li>
      )}
      {(p.locked_fields ?? []).length > 0 && (
        <li className="inline-flex items-start gap-1 sm:col-span-2">
          <Lock className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          {t('scans.ci.gatePolicy.lockedList', 'Locked: {fields}', {
            fields: (p.locked_fields ?? [])
              .map((f) =>
                f in GATE_FIELD_LABEL
                  ? t(`scans.ci.gateField.${f}`, GATE_FIELD_LABEL[f as GateField])
                  : f
              )
              .join(', '),
          })}
        </li>
      )}
      {p.enabled === false && <li>{t('scans.ci.disabled', 'Disabled')}</li>}
    </ul>
  )
}

/** The pipelines list filtered to repositories with their own gate settings. */
export const OVERRIDES_LIST_HREF = '/ci-cd?overrides=1'

function PolicyDialog({
  policy,
  overrideCounts,
  onClose,
  onSaved,
}: {
  policy: CIGatePolicy | null
  /** Per field, how many repository policies set it. */
  overrideCounts: Record<string, number>
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const { trigger: save, isMutating } = useSaveGatePolicy()
  const isNew = !policy?.id
  const [scopeType, setScopeType] = useState(policy?.scope_type ?? 'repository')
  const [scopeId, setScopeId] = useState(policy?.scope_id ?? '')
  const [mode, setMode] = useState(policy?.mode ?? 'enforce')
  const [severity, setSeverity] = useState(policy?.fail_on_severity ?? 'high')
  const [newOnly, setNewOnly] = useState(policy?.new_findings_only ?? true)
  const [kev, setKev] = useState(policy?.fail_on_kev ?? true)
  const [fixableOnly, setFixableOnly] = useState(policy?.fixable_only ?? false)
  const [epss, setEpss] = useState(
    policy?.epss_threshold !== undefined && policy?.epss_threshold !== null
      ? String(policy.epss_threshold)
      : ''
  )
  const [baselineFirstRun, setBaselineFirstRun] = useState(policy?.baseline_on_first_run ?? false)
  const [graceDays, setGraceDays] = useState(
    typeof policy?.baseline_grace_days === 'number' ? String(policy.baseline_grace_days) : ''
  )
  const [secretsBlock, setSecretsBlock] = useState(policy?.baseline_secrets_block ?? true)
  const [locked, setLocked] = useState<string[]>(policy?.locked_fields ?? [])
  const [reason, setReason] = useState(policy?.reason ?? '')
  // Locks apply to the layers below: the organization and business units.
  const canLock = scopeType === 'tenant' || scopeType === 'business_unit'
  const graceValue = graceDays.trim() === '' ? undefined : Number(graceDays)
  const graceInvalid =
    graceValue !== undefined &&
    (!Number.isInteger(graceValue) || graceValue < 1 || graceValue > 730)
  const epssValue = epss.trim() === '' ? undefined : Number(epss)
  const epssInvalid =
    epssValue !== undefined && (Number.isNaN(epssValue) || epssValue < 0 || epssValue > 1)

  const submit = async () => {
    if (epssInvalid)
      return toast.error(t('scans.ci.gatePolicy.epssInvalid', 'EPSS must be between 0 and 1'))
    try {
      await save({
        id: policy?.id,
        body: {
          scope_type: isNew ? scopeType : undefined,
          scope_id: isNew && scopeType !== 'tenant' ? scopeId.trim() : undefined,
          mode,
          fail_on_severity: severity,
          new_findings_only: newOnly,
          fail_on_kev: kev,
          epss_threshold: epssValue,
          fixable_only: fixableOnly,
          baseline_on_first_run: baselineFirstRun,
          // Replaced on every write (empty = no end), like epss_threshold.
          baseline_grace_days: graceValue,
          baseline_secrets_block: secretsBlock,
          locked_fields: canLock ? GATE_FIELDS.filter((f) => locked.includes(f)) : undefined,
          // reason and expires_at are replaced on every write: keep them.
          reason: scopeType === 'tenant' ? undefined : reason.trim() || undefined,
          expires_at: policy?.expires_at || undefined,
        },
      })
      toast.success(t('scans.ci.gatePolicy.saved', 'Gate policy saved'))
      onSaved()
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {isNew
              ? t('scans.ci.gatePolicy.addTitle', 'Add gate policy')
              : t('scans.ci.gatePolicy.editTitle', 'Edit gate policy')}
          </DialogTitle>
          <DialogDescription>
            {t('scans.ci.gatePolicy.dialogDescription', 'What fails a pipeline at this scope.')}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-3">
            {isNew && scopeType !== 'tenant' && (
              <>
                <Field label={t('scans.ci.gatePolicy.scope', 'Scope')} id="gp-scope">
                  <Select value={scopeType} onValueChange={setScopeType}>
                    <SelectTrigger id="gp-scope">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="repository">
                        {t('scans.ci.col.repository', 'Repository')}
                      </SelectItem>
                      <SelectItem value="business_unit">
                        {t('scans.ci.gatePolicy.businessUnit', 'Business unit')}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field
                  label={
                    scopeType === 'repository'
                      ? t('scans.ci.repositoryAssetId', 'Repository asset ID')
                      : t('scans.ci.gatePolicy.businessUnitId', 'Business unit ID')
                  }
                  id="gp-scope-id"
                >
                  <Input
                    id="gp-scope-id"
                    value={scopeId}
                    onChange={(e) => setScopeId(e.target.value)}
                  />
                </Field>
              </>
            )}
            <Field label={t('scans.ci.gatePolicy.mode', 'Mode')} id="gp-mode">
              <Select value={mode} onValueChange={setMode}>
                <SelectTrigger id="gp-mode">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="enforce">
                    {t('scans.ci.gatePolicy.enforce', 'Enforce')}
                  </SelectItem>
                  <SelectItem value="warn">
                    {t('scans.ci.gatePolicy.warn', 'Warn (report what would fail)')}
                  </SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t('scans.ci.gatePolicy.failOnSeverity', 'Fail on severity')} id="gp-sev">
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger id="gp-sev">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITY_OPTIONS.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s === 'none'
                        ? t('scans.ci.gatePolicy.severityNone', 'None')
                        : t('scans.ci.gatePolicy.severityAndAbove', '{severity} and above', {
                            severity: s,
                          })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field
              label={t('scans.ci.gatePolicy.epss', 'EPSS threshold (0 to 1, optional)')}
              id="gp-epss"
            >
              <Input
                id="gp-epss"
                inputMode="decimal"
                value={epss}
                onChange={(e) => setEpss(e.target.value)}
                aria-invalid={epssInvalid}
              />
            </Field>
            <SwitchRow
              id="gp-new"
              label={t(
                'scans.ci.gatePolicy.newOnly',
                'New findings only (compared with the default branch)'
              )}
              checked={newOnly}
              onChange={setNewOnly}
            />
            <SwitchRow
              id="gp-kev"
              label={t('scans.ci.gatePolicy.kevSwitch', 'Known exploited (KEV) fails')}
              checked={kev}
              onChange={setKev}
            />
            <SwitchRow
              id="gp-fixable-only"
              label={t(
                'scans.ci.gatePolicy.fixableOnlySwitch',
                'Dependency and image vulnerabilities block only when a fix exists'
              )}
              checked={fixableOnly}
              onChange={setFixableOnly}
            />
            <SwitchRow
              id="gp-baseline-first-run"
              label={t(
                'scans.ci.gatePolicy.baselineFirstRunSwitch',
                'Record the gate baseline on a repository’s first verified default-branch run'
              )}
              checked={baselineFirstRun}
              onChange={setBaselineFirstRun}
            />
            <Field
              label={t(
                'scans.ci.gatePolicy.graceDays',
                'Baseline grace (days, optional): baseline findings block again after it'
              )}
              id="gp-grace"
              hint={
                graceInvalid
                  ? t(
                      'scans.ci.repoSettings.graceInvalid',
                      'Whole days from 1 to 730, or empty for no end.'
                    )
                  : undefined
              }
            >
              <Input
                id="gp-grace"
                inputMode="numeric"
                value={graceDays}
                onChange={(e) => setGraceDays(e.target.value)}
                aria-invalid={graceInvalid}
              />
            </Field>
            <SwitchRow
              id="gp-baseline-secrets"
              label={t(
                'scans.ci.gatePolicy.baselineSecretsSwitch',
                'Secrets in the baseline still block default-branch runs'
              )}
              checked={secretsBlock}
              onChange={setSecretsBlock}
            />
            {scopeType !== 'tenant' && (
              <Field
                label={t(
                  'scans.ci.gatePolicy.reason',
                  'Reason (needed when a change loosens the gate)'
                )}
                id="gp-reason"
              >
                <Textarea
                  id="gp-reason"
                  value={reason}
                  maxLength={MAX_REASON}
                  rows={2}
                  onChange={(e) => setReason(e.target.value)}
                />
              </Field>
            )}
            {canLock && (
              <PolicyLocks
                scopeType={scopeType}
                locked={locked}
                onChange={setLocked}
                overrideCounts={scopeType === 'tenant' ? overrideCounts : {}}
              />
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            onClick={submit}
            disabled={
              isMutating ||
              epssInvalid ||
              graceInvalid ||
              (isNew && scopeType !== 'tenant' && !scopeId.trim())
            }
          >
            {t('common.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Per-field locks: a locked field can only be made stricter by the layers
 * below (business units, repositories). Removing a lock loosens the gate, so
 * the API asks for step-up. Each row also says how many repositories set the
 * field themselves, with a link to them.
 */
export function PolicyLocks({
  scopeType,
  locked,
  onChange,
  overrideCounts,
}: {
  scopeType: string
  locked: string[]
  onChange: (next: string[]) => void
  overrideCounts: Record<string, number>
}) {
  const { t } = useTranslation()
  return (
    <fieldset className="space-y-2 rounded-md border p-3">
      <legend className="px-1 text-sm font-medium">
        {scopeType === 'tenant'
          ? t('scans.ci.gatePolicy.locksOrg', 'Locks for business units and repositories')
          : t('scans.ci.gatePolicy.locksUnit', 'Locks for repositories')}
      </legend>
      <p className="text-xs text-muted-foreground">
        {t(
          'scans.ci.gatePolicy.locksHelp',
          'A locked field can only be made stricter below this policy. Removing a lock loosens the gate and asks you to confirm your identity.'
        )}
      </p>
      <ul className="divide-y">
        {GATE_FIELDS.map((f) => {
          const n = overrideCounts[f] ?? 0
          const on = locked.includes(f)
          return (
            <li key={f} className="flex items-center justify-between gap-3 py-1.5">
              <div className="min-w-0">
                <Label htmlFor={`gp-lock-${f}`} className="font-normal">
                  {t(`scans.ci.gateField.${f}`, GATE_FIELD_LABEL[f])}
                </Label>
                {n > 0 && (
                  <Link
                    href={OVERRIDES_LIST_HREF}
                    className="block text-xs text-primary hover:underline"
                    data-testid={`override-count-${f}`}
                  >
                    {n === 1
                      ? t('scans.ci.gatePolicy.oneOverride', '1 repository overrides this')
                      : t(
                          'scans.ci.gatePolicy.overrideCount',
                          '{count} repositories override this',
                          {
                            count: n,
                          }
                        )}
                  </Link>
                )}
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                {on && <Lock className="size-3.5 text-muted-foreground" aria-hidden />}
                <Switch
                  id={`gp-lock-${f}`}
                  checked={on}
                  aria-label={t('scans.ci.gatePolicy.lockLabel', 'Lock {field}', {
                    field: t(`scans.ci.gateField.${f}`, GATE_FIELD_LABEL[f]),
                  })}
                  onCheckedChange={(v) =>
                    onChange(v ? [...locked, f] : locked.filter((x) => x !== f))
                  }
                />
              </div>
            </li>
          )
        })}
      </ul>
    </fieldset>
  )
}

// ───────────────────────────────────────────────────── break-glass ───

function OverridesSection({ canOverride }: { canOverride: boolean }) {
  const { data, error, isLoading, mutate } = useGateOverrides()
  const { trigger: revoke } = useRevokeGateOverride()
  const [open, setOpen] = useState(false)
  const [pendingRevoke, setPendingRevoke] = useState<{ id: string; sha: string } | null>(null)
  const { t } = useTranslation()
  const overrides = data?.data ?? []

  if (error)
    return (
      <ErrorState
        title={t('scans.ci.breakGlass.list', 'break-glass overrides')}
        error={error}
        onRetry={() => mutate()}
      />
    )
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-2xl text-sm text-muted-foreground">
          {t(
            'scans.ci.breakGlass.description',
            'Let one commit of one repository pass the gate for a limited time. Every override and every run it lets through is recorded in the audit log.'
          )}
        </p>
        <GatedButton
          allowed={canOverride}
          reason={t(
            'scans.ci.breakGlass.noPermission',
            'Only owners and administrators can override the gate'
          )}
          size="sm"
          onClick={() => setOpen(true)}
        >
          <Plus className="size-4" aria-hidden /> {t('scans.ci.breakGlass.tab', 'Break-glass')}
        </GatedButton>
      </div>
      {isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : overrides.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t('scans.ci.breakGlass.empty', 'No overrides.')}
        </p>
      ) : (
        overrides.map((o) => (
          <Card key={o.id}>
            <CardContent className="flex flex-wrap items-center justify-between gap-2 p-4 text-sm">
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono">{shortSHA(o.commit_sha)}</span>
                  {o.active ? (
                    <Badge variant="destructive">{t('scans.ci.breakGlass.active', 'Active')}</Badge>
                  ) : (
                    <Badge variant="secondary">
                      {o.revoked_at
                        ? t('scans.ci.breakGlass.revoked', 'Revoked')
                        : t('scans.ci.breakGlass.expired', 'Expired')}
                    </Badge>
                  )}
                  <span className="text-muted-foreground">
                    {t('scans.ci.breakGlass.by', 'by {name}', {
                      name: o.created_by || t('scans.ci.breakGlass.anAdmin', 'an administrator'),
                    })}
                  </span>
                </div>
                <p className="break-words">{o.reason}</p>
                <p className="text-xs text-muted-foreground">
                  {t('scans.ci.breakGlass.until', 'Until {time} · repository {id}', {
                    time: o.expires_at ? new Date(o.expires_at).toLocaleString() : '',
                    id: o.repository_asset_id ?? '',
                  })}
                </p>
              </div>
              {o.active && (
                <GatedButton
                  allowed={canOverride}
                  reason={t(
                    'scans.ci.breakGlass.noRevokePermission',
                    'Only owners and administrators can revoke an override'
                  )}
                  variant="outline"
                  size="sm"
                  onClick={() => setPendingRevoke({ id: o.id ?? '', sha: shortSHA(o.commit_sha) })}
                >
                  {t('confirm.revoke', 'Revoke')}
                </GatedButton>
              )}
            </CardContent>
          </Card>
        ))
      )}
      <CIOverrideDialog open={open} onOpenChange={setOpen} onCreated={() => void mutate()} />
      <ConfirmDialog
        open={pendingRevoke !== null}
        onOpenChange={(o) => !o && setPendingRevoke(null)}
        destructive
        title={t('confirm.gateOverride.revokeTitle', 'Revoke the override for commit {sha}?', {
          sha: pendingRevoke?.sha ?? '',
        })}
        desc={t(
          'confirm.gateOverride.revokeDesc',
          'The commit is checked against the gate again from its next pipeline run, and fails it if its findings still do. A revoked override cannot be restored; create a new one if needed.'
        )}
        confirmText={t('confirm.revoke', 'Revoke')}
        handleConfirm={async () => {
          if (!pendingRevoke) return
          try {
            await revoke(pendingRevoke.id)
            toast.success(t('scans.ci.breakGlass.revokedToast', 'Override revoked'))
            setPendingRevoke(null)
            void mutate()
          } catch (e) {
            toast.error(getErrorMessage(e))
          }
        }}
      />
    </div>
  )
}

// ─────────────────────────────────────────────────────────── parts ───

function Field({
  label,
  id,
  hint,
  children,
}: {
  label: string
  id: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

function SwitchRow({
  id,
  label,
  checked,
  onChange,
  disabled,
}: {
  id: string
  label: string
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
      <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled} />
    </div>
  )
}
