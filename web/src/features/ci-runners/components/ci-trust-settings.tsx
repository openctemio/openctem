'use client'

/**
 * CI trust and gate settings (api RFC-051):
 *   - trust configurations: which GitHub Actions / GitLab CI pipelines may
 *     exchange their OIDC token for a short-lived upload token;
 *   - gate policy: what fails a pipeline (secrets always fail, accepted risk
 *     is always honored);
 *   - break-glass: let one commit pass for a limited time, audited.
 * Writes need scans:ci:write / scans:ci:override (owners and admins); the API
 * is the authority, the page only hides what the caller cannot do.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Check, Copy, KeyRound, Plus, ShieldAlert, Trash2 } from 'lucide-react'
import { PageHeader, EmptyState, ErrorState, GatedButton } from '@/features/shared'
import { CIRequireOIDC } from './ci-require-oidc'
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  useCreateGateOverride,
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
  PROVIDER_LABEL,
  SEVERITY_OPTIONS,
  defaultAudience,
  joinList,
  parseList,
  shortSHA,
  snippetFor,
} from '../lib/ci'
import type { CIGatePolicy, CIProvider, CITrustConfig } from '../types'

const NO_WRITE = 'Only owners and administrators can change CI trust and the gate'

export function CITrustSettings() {
  const { can } = usePermissions()
  const canWrite = can(Permission.CIWrite)
  const canOverride = can(Permission.CIOverride)
  return (
    <div className="space-y-4">
      <PageHeader
        title="CI pipelines"
        description="Let GitHub Actions and GitLab CI jobs send results with their own identity instead of a stored API key, and decide what fails a pipeline."
      />
      <CIRequireOIDC canWrite={canWrite} />
      <Tabs defaultValue="trust">
        <TabsList>
          <TabsTrigger value="trust">Trust</TabsTrigger>
          <TabsTrigger value="gate">Gate policy</TabsTrigger>
          <TabsTrigger value="break-glass">Break-glass</TabsTrigger>
        </TabsList>
        <TabsContent value="trust" className="mt-4">
          <TrustConfigsSection canWrite={canWrite} />
        </TabsContent>
        <TabsContent value="gate" className="mt-4">
          <GatePolicySection canWrite={canWrite} />
        </TabsContent>
        <TabsContent value="break-glass" className="mt-4">
          <OverridesSection canOverride={canOverride} />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// ─────────────────────────────────────────────────────────── trust ───

function rulesSummary(c: CITrustConfig): string {
  const r = c.rules ?? {}
  const parts: string[] = []
  if (r.owners?.length) parts.push(`owners ${joinList(r.owners)}`)
  if (r.repositories?.length) parts.push(`repositories ${joinList(r.repositories)}`)
  if (r.refs?.length) parts.push(`refs ${joinList(r.refs)}`)
  if (r.environments?.length) parts.push(`environments ${joinList(r.environments)}`)
  if (r.events?.length) parts.push(`events ${joinList(r.events)}`)
  return parts.join(' · ')
}

function TrustConfigsSection({ canWrite }: { canWrite: boolean }) {
  const { data, error, isLoading, mutate } = useTrustConfigs()
  const { trigger: remove } = useDeleteTrustConfig()
  const [editing, setEditing] = useState<CITrustConfig | 'new' | null>(null)
  const [snippetOf, setSnippetOf] = useState<CITrustConfig | null>(null)
  const [deleting, setDeleting] = useState<CITrustConfig | null>(null)
  const configs = data?.data ?? []

  if (error)
    return <ErrorState title="CI trust configurations" error={error} onRetry={() => mutate()} />
  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <GatedButton
          allowed={canWrite}
          reason={NO_WRITE}
          size="sm"
          onClick={() => setEditing('new')}
        >
          <Plus className="size-4" aria-hidden /> Add trust
        </GatedButton>
      </div>
      {isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : configs.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="No CI trust yet"
          description="Name the organizations or repositories whose pipelines may send results. Each job proves who it is with its OIDC token and gets an upload token that expires within 15 minutes."
        />
      ) : (
        configs.map((c) => (
          <Card key={c.id}>
            <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
              <div className="min-w-0 space-y-1">
                <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                  {c.name}
                  <Badge variant="outline">{PROVIDER_LABEL[c.provider ?? ''] ?? c.provider}</Badge>
                  {!c.enabled && <Badge variant="secondary">Disabled</Badge>}
                  {c.rules?.allow_fork_pull_requests && (
                    <Badge variant="destructive">Fork pull requests</Badge>
                  )}
                </CardTitle>
                <CardDescription className="break-all">{rulesSummary(c)}</CardDescription>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setSnippetOf(c)}>
                  Pipeline snippet
                </Button>
                <GatedButton
                  allowed={canWrite}
                  reason={NO_WRITE}
                  variant="outline"
                  size="sm"
                  onClick={() => setEditing(c)}
                >
                  Edit
                </GatedButton>
                <GatedButton
                  allowed={canWrite}
                  reason={NO_WRITE}
                  variant="ghost"
                  size="sm"
                  aria-label={`Delete ${c.name}`}
                  onClick={() => setDeleting(c)}
                >
                  <Trash2 className="size-4" aria-hidden />
                </GatedButton>
              </div>
            </CardHeader>
            <CardContent className="grid gap-1 text-sm text-muted-foreground sm:grid-cols-2">
              <span className="break-all">Issuer: {c.issuer}</span>
              <span className="break-all">Audience: {c.audience}</span>
              <span>Default branch: {c.default_branch}</span>
              <span>
                Last used: {c.last_used_at ? new Date(c.last_used_at).toLocaleString() : 'never'}
              </span>
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
      {snippetOf && <SnippetDialog config={snippetOf} onClose={() => setSnippetOf(null)} />}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete CI trust"
        desc={`Pipelines admitted by "${deleting?.name ?? ''}" can no longer send results. Tokens already issued expire within 15 minutes.`}
        confirmText="Delete"
        destructive
        handleConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target?.id) return
          remove(target.id)
            .then(() => {
              toast.success('CI trust deleted')
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
  const { currentTenant } = useTenant()
  const { trigger: save, isMutating } = useSaveTrustConfig()
  const [name, setName] = useState(config?.name ?? '')
  const [provider, setProvider] = useState<CIProvider>((config?.provider as CIProvider) ?? 'github')
  const [issuer, setIssuer] = useState(config?.issuer ?? '')
  const [audience, setAudience] = useState(config?.audience ?? '')
  const [defaultBranch, setDefaultBranch] = useState(config?.default_branch ?? 'main')
  const [owners, setOwners] = useState(joinList(config?.rules?.owners))
  const [repositories, setRepositories] = useState(joinList(config?.rules?.repositories))
  const [refs, setRefs] = useState(joinList(config?.rules?.refs))
  const [environments, setEnvironments] = useState(joinList(config?.rules?.environments))
  const [events, setEvents] = useState(joinList(config?.rules?.events))
  const [allowForks, setAllowForks] = useState(!!config?.rules?.allow_fork_pull_requests)
  const [protectedRef, setProtectedRef] = useState(!!config?.rules?.require_protected_ref)
  const [enabled, setEnabled] = useState(config?.enabled ?? true)

  const noScope = parseList(owners).length === 0 && parseList(repositories).length === 0
  const submit = async () => {
    if (!name.trim()) return toast.error('Name is required')
    if (noScope) return toast.error('Name at least one owner or repository')
    try {
      const saved = await save({
        id: config?.id,
        body: {
          name: name.trim(),
          provider,
          issuer: provider === 'gitlab' ? issuer.trim() || undefined : undefined,
          audience: audience.trim() || undefined,
          default_branch: defaultBranch.trim() || undefined,
          enabled,
          rules: {
            owners: parseList(owners),
            repositories: parseList(repositories),
            refs: parseList(refs),
            environments: parseList(environments),
            events: parseList(events),
            allow_fork_pull_requests: allowForks,
            require_protected_ref: protectedRef,
          },
        },
      })
      toast.success(config ? 'CI trust updated' : 'CI trust added')
      onSaved(saved)
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{config ? 'Edit CI trust' : 'Add CI trust'}</DialogTitle>
          <DialogDescription>
            A pipeline is admitted when every rule you fill in matches its token. Lists are comma
            separated; patterns use * for one path segment and ** for any depth.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Field label="Name" id="ci-name">
            <Input id="ci-name" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Provider" id="ci-provider">
            <Select
              value={provider}
              onValueChange={(v) => setProvider(v as CIProvider)}
              disabled={!!config}
            >
              <SelectTrigger id="ci-provider">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="github">GitHub Actions</SelectItem>
                <SelectItem value="gitlab">GitLab CI</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {provider === 'gitlab' && (
            <Field label="GitLab URL (issuer)" id="ci-issuer" hint="Leave empty for gitlab.com.">
              <Input
                id="ci-issuer"
                placeholder="https://gitlab.com"
                value={issuer}
                onChange={(e) => setIssuer(e.target.value)}
              />
            </Field>
          )}
          <Field
            label="Owners"
            id="ci-owners"
            hint={provider === 'gitlab' ? 'Top-level groups.' : 'Organizations or users.'}
          >
            <Input
              id="ci-owners"
              placeholder="acme"
              value={owners}
              onChange={(e) => setOwners(e.target.value)}
            />
          </Field>
          <Field label="Repositories" id="ci-repos" hint="owner/name, owner/* or owner/**.">
            <Input
              id="ci-repos"
              placeholder="acme/api, acme/web"
              value={repositories}
              onChange={(e) => setRepositories(e.target.value)}
            />
          </Field>
          <Field
            label="Branches and tags"
            id="ci-refs"
            hint="Empty admits every ref. For a pull request, its source branch."
          >
            <Input
              id="ci-refs"
              placeholder="main, release/*"
              value={refs}
              onChange={(e) => setRefs(e.target.value)}
            />
          </Field>
          <Field
            label="Environments"
            id="ci-envs"
            hint="Optional: require a deployment environment."
          >
            <Input
              id="ci-envs"
              value={environments}
              onChange={(e) => setEnvironments(e.target.value)}
            />
          </Field>
          <Field
            label="Events"
            id="ci-events"
            hint="Optional: push, pull_request, merge_request_event, schedule..."
          >
            <Input id="ci-events" value={events} onChange={(e) => setEvents(e.target.value)} />
          </Field>
          <Field
            label="Default branch"
            id="ci-default"
            hint="The baseline when the platform does not know the repository's default branch yet."
          >
            <Input
              id="ci-default"
              value={defaultBranch}
              onChange={(e) => setDefaultBranch(e.target.value)}
            />
          </Field>
          <Field
            label="Audience"
            id="ci-aud"
            hint={`Default: ${defaultAudience(currentTenant?.id ?? '<tenant id>')}`}
          >
            <Input id="ci-aud" value={audience} onChange={(e) => setAudience(e.target.value)} />
          </Field>
          <SwitchRow
            id="ci-protected"
            label="Protected branches and tags only"
            checked={protectedRef}
            onChange={setProtectedRef}
          />
          {protectedRef && provider === 'github' && (
            <p className="text-muted-foreground text-xs">
              GitHub tokens do not say whether a ref is protected. List the deployment environments
              above whose deployment branch rules admit only protected branches and tags; only jobs
              running in one of them are admitted.
            </p>
          )}
          <SwitchRow
            id="ci-forks"
            label="Admit fork pull requests"
            checked={allowForks}
            onChange={setAllowForks}
          />
          {allowForks && (
            <Alert variant="destructive">
              <ShieldAlert />
              <AlertTitle>Fork code would act with this repository&apos;s identity</AlertTitle>
              <AlertDescription>
                Events such as pull_request_target run code from a fork. Leave this off unless the
                workflow never checks out fork code.
              </AlertDescription>
            </Alert>
          )}
          <SwitchRow id="ci-enabled" label="Enabled" checked={enabled} onChange={setEnabled} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isMutating || noScope || !name.trim()}>
            {config ? 'Save' : 'Add'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function SnippetDialog({ config, onClose }: { config: CITrustConfig; onClose: () => void }) {
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
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Pipeline snippet</DialogTitle>
          <DialogDescription>
            The job asks its CI provider for an OIDC token and exchanges it for a run token. Nothing
            secret goes into CI; the token is never printed. The job fails when the gate does.
          </DialogDescription>
        </DialogHeader>
        <pre
          className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs"
          data-testid="ci-snippet"
        >
          {snippet}
        </pre>
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
            Copy
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ──────────────────────────────────────────────────────────── gate ───

function policyScope(p: CIGatePolicy): string {
  if (p.scope_type === 'tenant') return 'Organization'
  if (p.scope_type === 'business_unit') return `Business unit ${p.scope_id ?? ''}`
  return `Repository ${p.scope_id ?? ''}`
}

function GatePolicySection({ canWrite }: { canWrite: boolean }) {
  const { data, error, isLoading, mutate } = useGatePolicies()
  const { trigger: remove } = useDeleteGatePolicy()
  const [editing, setEditing] = useState<CIGatePolicy | null>(null)
  const [adding, setAdding] = useState(false)
  const policies = data?.data ?? []
  const tenantPolicy = policies.find((p) => p.scope_type === 'tenant')
  const others = policies.filter((p) => p.scope_type !== 'tenant')

  if (error) return <ErrorState title="gate policies" error={error} onRetry={() => mutate()} />
  if (isLoading) return <Skeleton className="h-40 w-full" />
  const shown = tenantPolicy ?? data?.default
  return (
    <div className="space-y-4">
      <Alert>
        <ShieldAlert />
        <AlertTitle>Always on</AlertTitle>
        <AlertDescription>
          A committed secret always fails the pipeline. Accepted risk, false positives and
          suppressions are always honored. A scanner that fails to run fails the pipeline.
        </AlertDescription>
      </Alert>
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-base">Organization policy</CardTitle>
            <CardDescription>
              {tenantPolicy
                ? 'Applies to every repository without its own policy.'
                : 'Built-in default: no organization policy is set.'}
            </CardDescription>
          </div>
          <GatedButton
            allowed={canWrite}
            reason={NO_WRITE}
            size="sm"
            variant="outline"
            onClick={() => setEditing(tenantPolicy ?? { scope_type: 'tenant' })}
          >
            {tenantPolicy ? 'Edit' : 'Set policy'}
          </GatedButton>
        </CardHeader>
        <CardContent className="text-sm">{shown ? <PolicySummary p={shown} /> : null}</CardContent>
      </Card>
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium">Business unit and repository policies</h2>
        <GatedButton allowed={canWrite} reason={NO_WRITE} size="sm" onClick={() => setAdding(true)}>
          <Plus className="size-4" aria-hidden /> Add policy
        </GatedButton>
      </div>
      {others.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          None. A repository uses its own policy, else the strictest of its business units&apos;,
          else the organization&apos;s.
        </p>
      ) : (
        others.map((p) => (
          <Card key={p.id}>
            <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
              <CardTitle className="break-all text-sm">{policyScope(p)}</CardTitle>
              <div className="flex gap-2">
                <GatedButton
                  allowed={canWrite}
                  reason={NO_WRITE}
                  variant="outline"
                  size="sm"
                  onClick={() => setEditing(p)}
                >
                  Edit
                </GatedButton>
                <GatedButton
                  allowed={canWrite}
                  reason={NO_WRITE}
                  variant="ghost"
                  size="sm"
                  aria-label="Delete policy"
                  onClick={async () => {
                    try {
                      await remove(p.id ?? '')
                      void mutate()
                    } catch (e) {
                      toast.error(getErrorMessage(e))
                    }
                  }}
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
    </div>
  )
}

function PolicySummary({ p }: { p: CIGatePolicy }) {
  return (
    <ul className="grid gap-1 text-muted-foreground sm:grid-cols-2">
      <li>Mode: {p.mode === 'warn' ? 'warn (report, never fail)' : 'enforce'}</li>
      <li>
        Fails on:{' '}
        {p.fail_on_severity === 'none' ? 'no severity' : `${p.fail_on_severity} and above`}
      </li>
      <li>
        {p.new_findings_only
          ? 'New findings only (compared with the default branch)'
          : 'Every finding'}
      </li>
      <li>Known exploited (KEV): {p.fail_on_kev ? 'fails' : 'does not fail'}</li>
      {p.epss_threshold !== undefined && p.epss_threshold !== null && (
        <li>EPSS at least {p.epss_threshold}</li>
      )}
      {p.enabled === false && <li>Disabled</li>}
    </ul>
  )
}

function PolicyDialog({
  policy,
  onClose,
  onSaved,
}: {
  policy: CIGatePolicy | null
  onClose: () => void
  onSaved: () => void
}) {
  const { trigger: save, isMutating } = useSaveGatePolicy()
  const isNew = !policy?.id
  const [scopeType, setScopeType] = useState(policy?.scope_type ?? 'repository')
  const [scopeId, setScopeId] = useState(policy?.scope_id ?? '')
  const [mode, setMode] = useState(policy?.mode ?? 'enforce')
  const [severity, setSeverity] = useState(policy?.fail_on_severity ?? 'high')
  const [newOnly, setNewOnly] = useState(policy?.new_findings_only ?? true)
  const [kev, setKev] = useState(policy?.fail_on_kev ?? true)
  const [epss, setEpss] = useState(
    policy?.epss_threshold !== undefined && policy?.epss_threshold !== null
      ? String(policy.epss_threshold)
      : ''
  )
  const epssValue = epss.trim() === '' ? undefined : Number(epss)
  const epssInvalid =
    epssValue !== undefined && (Number.isNaN(epssValue) || epssValue < 0 || epssValue > 1)

  const submit = async () => {
    if (epssInvalid) return toast.error('EPSS must be between 0 and 1')
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
        },
      })
      toast.success('Gate policy saved')
      onSaved()
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{isNew ? 'Add gate policy' : 'Edit gate policy'}</DialogTitle>
          <DialogDescription>What fails a pipeline at this scope.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          {isNew && scopeType !== 'tenant' && (
            <>
              <Field label="Scope" id="gp-scope">
                <Select value={scopeType} onValueChange={setScopeType}>
                  <SelectTrigger id="gp-scope">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="repository">Repository</SelectItem>
                    <SelectItem value="business_unit">Business unit</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field
                label={scopeType === 'repository' ? 'Repository asset ID' : 'Business unit ID'}
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
          <Field label="Mode" id="gp-mode">
            <Select value={mode} onValueChange={setMode}>
              <SelectTrigger id="gp-mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="enforce">Enforce</SelectItem>
                <SelectItem value="warn">Warn (report what would fail)</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label="Fail on severity" id="gp-sev">
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger id="gp-sev">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SEVERITY_OPTIONS.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s === 'none' ? 'None' : `${s} and above`}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="EPSS threshold (0 to 1, optional)" id="gp-epss">
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
            label="New findings only (compared with the default branch)"
            checked={newOnly}
            onChange={setNewOnly}
          />
          <SwitchRow
            id="gp-kev"
            label="Known exploited (KEV) fails"
            checked={kev}
            onChange={setKev}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={submit}
            disabled={
              isMutating || epssInvalid || (isNew && scopeType !== 'tenant' && !scopeId.trim())
            }
          >
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ───────────────────────────────────────────────────── break-glass ───

function OverridesSection({ canOverride }: { canOverride: boolean }) {
  const { data, error, isLoading, mutate } = useGateOverrides()
  const { trigger: create, isMutating } = useCreateGateOverride()
  const { trigger: revoke } = useRevokeGateOverride()
  const [open, setOpen] = useState(false)
  const [assetId, setAssetId] = useState('')
  const [sha, setSha] = useState('')
  const [reason, setReason] = useState('')
  const [hours, setHours] = useState('24')
  const overrides = data?.data ?? []
  const hoursValue = Number(hours)
  const invalid =
    !assetId.trim() ||
    !/^[0-9a-fA-F]{7,64}$/.test(sha.trim()) ||
    reason.trim().length < 10 ||
    !(hoursValue >= 1 && hoursValue <= 168)

  if (error)
    return <ErrorState title="break-glass overrides" error={error} onRetry={() => mutate()} />
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-2xl text-sm text-muted-foreground">
          Let one commit of one repository pass the gate for a limited time. Every override and
          every run it lets through is recorded in the audit log.
        </p>
        <GatedButton
          allowed={canOverride}
          reason="Only owners and administrators can override the gate"
          size="sm"
          onClick={() => setOpen(true)}
        >
          <Plus className="size-4" aria-hidden /> Break-glass
        </GatedButton>
      </div>
      {isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : overrides.length === 0 ? (
        <p className="text-sm text-muted-foreground">No overrides.</p>
      ) : (
        overrides.map((o) => (
          <Card key={o.id}>
            <CardContent className="flex flex-wrap items-center justify-between gap-2 p-4 text-sm">
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono">{shortSHA(o.commit_sha)}</span>
                  {o.active ? (
                    <Badge variant="destructive">Active</Badge>
                  ) : (
                    <Badge variant="secondary">{o.revoked_at ? 'Revoked' : 'Expired'}</Badge>
                  )}
                  <span className="text-muted-foreground">
                    by {o.created_by || 'an administrator'}
                  </span>
                </div>
                <p className="break-words">{o.reason}</p>
                <p className="text-xs text-muted-foreground">
                  Until {o.expires_at ? new Date(o.expires_at).toLocaleString() : ''} · repository{' '}
                  {o.repository_asset_id}
                </p>
              </div>
              {o.active && (
                <GatedButton
                  allowed={canOverride}
                  reason="Only owners and administrators can revoke an override"
                  variant="outline"
                  size="sm"
                  onClick={async () => {
                    try {
                      await revoke(o.id ?? '')
                      toast.success('Override revoked')
                      void mutate()
                    } catch (e) {
                      toast.error(getErrorMessage(e))
                    }
                  }}
                >
                  Revoke
                </GatedButton>
              )}
            </CardContent>
          </Card>
        ))
      )}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Break-glass</DialogTitle>
            <DialogDescription>
              The commit passes the gate until the override expires or is revoked.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <Field label="Repository asset ID" id="ov-asset">
              <Input id="ov-asset" value={assetId} onChange={(e) => setAssetId(e.target.value)} />
            </Field>
            <Field label="Commit" id="ov-sha" hint="Full or abbreviated (at least 7 characters).">
              <Input
                id="ov-sha"
                className="font-mono"
                value={sha}
                onChange={(e) => setSha(e.target.value)}
              />
            </Field>
            <Field
              label="Reason"
              id="ov-reason"
              hint="At least 10 characters; recorded in the audit log."
            >
              <Textarea id="ov-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            </Field>
            <Field label="Hours (1 to 168)" id="ov-hours">
              <Input
                id="ov-hours"
                inputMode="numeric"
                value={hours}
                onChange={(e) => setHours(e.target.value)}
              />
            </Field>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={invalid || isMutating}
              onClick={async () => {
                try {
                  await create({
                    repository_asset_id: assetId.trim(),
                    commit_sha: sha.trim(),
                    reason: reason.trim(),
                    expires_in_hours: hoursValue,
                  })
                  toast.success('Override created')
                  setOpen(false)
                  setAssetId('')
                  setSha('')
                  setReason('')
                  void mutate()
                } catch (e) {
                  toast.error(getErrorMessage(e))
                }
              }}
            >
              Override the gate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
}: {
  id: string
  label: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  )
}
