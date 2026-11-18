'use client'

/**
 * A CI trust configuration's rules form and its pipeline snippet (api
 * RFC-051). The configuration sheet shows both in place; a new
 * configuration made outside the connect flow's steps uses the dialog.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Check, ChevronDown, Copy, ShieldAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { useTranslation } from '@/context/i18n-provider'
import { useBrand } from '@/context/brand-provider'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, usePermissions } from '@/lib/permissions'
import { useCIRunnerRelease, useSaveTrustConfig } from '../api/use-ci'
import {
  CI_PROVIDERS,
  PROVIDER_LABEL,
  PROVIDER_TRAITS,
  defaultAudience,
  issuerFor,
  joinList,
  organizationFromIssuer,
  parseList,
  snippetFor,
} from '../lib/ci'
import { issuerHost, normaliseIssuer, type RefusalFix } from '../lib/connect'
import type { CIProvider, CITrustConfig, CITrustConfigRequest } from '../types'
import { CITrustPreview } from './ci-trust-preview'
import { manageScopeSupported } from './ci-trust-scope'
import { CIPipelineDefinitions } from './ci-pipeline-definitions'
import { fixLabel } from './ci-refusals'
import { Field, SwitchRow } from './ci-form-parts'

/** A list with one more entry (kept once). */
function withEntry(list: string[] | undefined, v: string): string[] {
  const l = list ?? []
  return l.includes(v) ? l : [...l, v]
}

/**
 * A trust configuration's rules. In a dialog for a new configuration (the
 * connect flow's "Fill in every rule yourself"), inline in the
 * configuration's sheet for an existing one.
 */
export function TrustConfigForm({
  config,
  prefill,
  onClose,
  onSaved,
  inline = false,
}: {
  config: CITrustConfig | null
  /** A refused pipeline's fix: the change is shown here and saved only by Save. */
  prefill?: RefusalFix
  onClose: () => void
  onSaved: (c: CITrustConfig) => void
  /** Render the fields and buttons in place (the configuration sheet's Rules tab). */
  inline?: boolean
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
  const [repositories, setRepositories] = useState(
    joinList(
      prefill?.kind === 'allowRepository'
        ? withEntry(config?.rules?.repositories, prefill.value)
        : config?.rules?.repositories
    )
  )
  const [refs, setRefs] = useState(
    joinList(
      prefill?.kind === 'allowBranch'
        ? withEntry(config?.rules?.refs, prefill.value)
        : config?.rules?.refs
    )
  )
  const [environments, setEnvironments] = useState(joinList(config?.rules?.environments))
  const [events, setEvents] = useState(joinList(config?.rules?.events))
  const [workflowRefs, setWorkflowRefs] = useState<string[]>(
    prefill?.kind === 'addDefinition'
      ? withEntry(config?.rules?.workflow_refs, prefill.value)
      : (config?.rules?.workflow_refs ?? [])
  )
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
    if (!PROVIDER_TRAITS[p].workflowRefs) setWorkflowRefs([])
  }

  const body = (): CITrustConfigRequest => ({
    name: name.trim() || 'preview',
    provider,
    issuer:
      provider === 'github'
        ? organization.trim() || undefined
        : provider === 'gitlab'
          ? normaliseIssuer(organization) || undefined
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
      workflow_refs: traits.workflowRefs ? workflowRefs : [],
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
  const gitlabIssuer = normaliseIssuer(organization) || 'https://gitlab.com'
  // Rules past the basics are folded; open when one is set or a fix needs it.
  const [more, setMore] = useState(
    prefill?.kind === 'addDefinition' ||
      prefill?.kind === 'openDefinitions' ||
      !!config?.rules?.environments?.length ||
      !!config?.rules?.events?.length ||
      !!config?.rules?.workflow_refs?.length ||
      !!config?.rules?.allow_fork_pull_requests
  )
  const wholeGroup =
    parseList(owners).length > 0 || parseList(repositories).some((r) => r.endsWith('*'))
  const fields = (
    <div className="space-y-3">
      {prefill && (
        <p className="rounded-md border p-3 text-sm" data-testid="ci-fix-note">
          {t('scans.ci.fix.review', '{fix}: check the change below, then save.', {
            fix: fixLabel(prefill, t),
          })}
        </p>
      )}
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
          hint={t(
            'scans.ci.connect.addressShown',
            'Leave empty for gitlab.com. Tokens must name exactly: {issuer}',
            { issuer: gitlabIssuer }
          )}
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
              placeholder={t('scans.ci.trust.workspacePlaceholder', 'acme')}
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
              : t('scans.ci.trust.ownersHint', 'Organizations or users that own the repositories.')
        }
      >
        <Input
          id="ci-owners"
          placeholder={t('scans.ci.trust.ownersPlaceholder', 'acme')}
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
          placeholder={t('scans.ci.trust.refsPlaceholder', 'main, release/*')}
          value={refs}
          onChange={(e) => setRefs(e.target.value)}
        />
      </Field>
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
      <Collapsible open={more} onOpenChange={setMore}>
        <CollapsibleTrigger asChild>
          <Button type="button" variant="ghost" size="sm" aria-expanded={more}>
            <ChevronDown
              className={more ? 'rotate-180 transition-transform' : 'transition-transform'}
              aria-hidden
            />
            {t('scans.ci.trust.moreRules', 'More rules')}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-3 pt-2">
          {traits.workflowRefs && (
            <CIPipelineDefinitions
              provider={provider}
              host={provider === 'gitlab' ? issuerHost(gitlabIssuer) : ''}
              value={workflowRefs}
              onChange={setWorkflowRefs}
              wholeGroup={wholeGroup}
            />
          )}
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
            // submit-error-ok: a warning about the choice, not a failed submit
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
        </CollapsibleContent>
      </Collapsible>
      <SwitchRow
        id="ci-enabled"
        label={t('scans.ci.enabled', 'Enabled')}
        checked={enabled}
        onChange={setEnabled}
      />
      {!needsIssuer && (
        <CITrustPreview
          provider={provider}
          draft={body}
          onUseIssuer={
            traits.issuerInput === 'url' || provider === 'github' || provider === 'gitlab'
              ? setOrganization
              : undefined
          }
        />
      )}
    </div>
  )
  const buttons = (
    <>
      <Button variant="outline" onClick={onClose}>
        {t('common.cancel', 'Cancel')}
      </Button>
      <Button onClick={submit} disabled={isMutating || noScope || needsIssuer || !name.trim()}>
        {config ? t('common.save', 'Save') : t('scans.ci.add', 'Add')}
      </Button>
    </>
  )
  if (inline)
    return (
      <div className="space-y-4" data-testid="ci-trust-rules">
        {fields}
        <div className="flex flex-wrap justify-end gap-2">{buttons}</div>
      </div>
    )
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
        <DialogBody>{fields}</DialogBody>
        <DialogFooter>{buttons}</DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The pipeline snippet of a configuration: who it admits, the steps, Copy. */
function useSnippet(config: CITrustConfig): string {
  const { currentTenant } = useTenant()
  const brand = useBrand()
  const release = useCIRunnerRelease()
  return useMemo(
    () =>
      snippetFor((config.provider as CIProvider) ?? 'github', {
        apiUrl:
          typeof window === 'undefined' ? 'https://openctem.example.com' : window.location.origin,
        tenantId: currentTenant?.id ?? '',
        audience: config.audience ?? '',
        productName: brand.name,
        release,
      }),
    [config, currentTenant, brand.name, release]
  )
}

function SnippetBody({ config, snippet }: { config: CITrustConfig; snippet: string }) {
  const { t } = useTranslation()
  return (
    <>
      {!!config.rules?.workflow_refs?.length && (
        <p className="mb-2 text-sm text-muted-foreground" data-testid="ci-snippet-workflow-refs">
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
    </>
  )
}

function CopyButton({ text }: { text: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={async () => {
        await copyToClipboard(text)
        setCopied(true)
      }}
    >
      {copied ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
      {copied ? t('scans.ci.copied', 'Copied') : t('scans.ci.copy', 'Copy')}
    </Button>
  )
}

/** The snippet in place (the configuration sheet's Snippet tab). */
export function SnippetPanel({ config }: { config: CITrustConfig }) {
  const { t } = useTranslation()
  const snippet = useSnippet(config)
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        {t(
          'scans.ci.trust.snippetDescription',
          'The job asks its CI provider for an OIDC token and exchanges it for a run token. Nothing secret goes into CI; the token is never printed. The job fails when the gate does.'
        )}
      </p>
      <SnippetBody config={config} snippet={snippet} />
      <CopyButton text={snippet} />
    </div>
  )
}

/** The snippet right after a new configuration is added. */
export function SnippetDialog({ config, onClose }: { config: CITrustConfig; onClose: () => void }) {
  const { t } = useTranslation()
  const snippet = useSnippet(config)
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
          <SnippetBody config={config} snippet={snippet} />
        </DialogBody>
        <DialogFooter>
          <CopyButton text={snippet} />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
