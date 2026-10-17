'use client'

/**
 * Connect a pipeline (api RFC-051): pick the CI system, name the organization
 * whose pipelines may report, create the trust configuration, copy the
 * pipeline snippet, then wait for the first run. While waiting, the dialog
 * polls the runs and the refused exchanges, so a refused pipeline shows the
 * rule that refused it and how to fix it instead of silence.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Check, CircleCheck, Copy, Loader2 } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
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
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { useBrand } from '@/context/brand-provider'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import {
  useCIRuns,
  useSCMApps,
  useSaveTrustConfig,
  useTrustConfigs,
  useTrustRefusals,
} from '../api/use-ci'
import {
  CI_PROVIDERS,
  PROVIDER_LABEL,
  PROVIDER_TRAITS,
  findCoveringTrust,
  issuerFor,
  parseList,
  snippetFor,
} from '../lib/ci'
import type { CIProvider, CITrustConfig, CITrustConfigRequest } from '../types'
import { RefusalDetail } from './ci-refusals'

/** How often the waiting step polls runs and refusals. */
export const SETUP_POLL_MS = 10_000

const STEPS = ['provider', 'organization', 'snippet', 'waiting'] as const
type Step = (typeof STEPS)[number]

export function CISetupWizard({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const [step, setStep] = useState<Step>('provider')
  const [provider, setProvider] = useState<CIProvider>('github')
  const [issuer, setIssuer] = useState('')
  const [owners, setOwners] = useState('')
  const [defaultBranch, setDefaultBranch] = useState('main')
  const [created, setCreated] = useState<CITrustConfig | null>(null)
  // True when an existing trust configuration already admitted the owners and
  // the wizard reuses it rather than creating a duplicate.
  const [reused, setReused] = useState(false)
  const [copied, setCopied] = useState(false)
  // Runs and refusals older than the moment the configuration was created
  // are not this pipeline's.
  const [since, setSince] = useState(0)
  const { trigger: save, isMutating } = useSaveTrustConfig()
  const traits = PROVIDER_TRAITS[provider]

  const scm = useSCMApps()
  const trusts = useTrustConfigs({ enabled: open })
  const suggestions = useMemo(
    () =>
      provider === 'github'
        ? (scm.data?.data ?? [])
            .filter((i) => i.provider === 'github' && i.account_login)
            .map((i) => i.account_login as string)
        : [],
    [provider, scm.data]
  )

  const waiting = step === 'waiting'
  const runs = useCIRuns(
    { provider, perPage: 10 },
    { enabled: open && waiting, refreshInterval: SETUP_POLL_MS }
  )
  const refusals = useTrustRefusals({ enabled: open && waiting, refreshInterval: SETUP_POLL_MS })
  // A reused configuration has runs from before: only a run that started
  // after this dialog counts as the first one.
  const firstRun = (runs.data?.data ?? []).find(
    (r) =>
      (!reused && created?.id && r.trust_config_id === created.id) ||
      (!!r.created_at && Date.parse(r.created_at) >= since)
  )
  const lastRefusal = (refusals.data?.data ?? []).find((r) => !!r.at && Date.parse(r.at) >= since)

  const needsIssuer = traits.issuerInput !== 'fixed' && provider !== 'gitlab'
  const ownersLabel = traits.repositoriesById
    ? t('scans.ci.setup.repositoryIds', 'Repository UUIDs')
    : t('scans.ci.setup.owners', 'Organizations or owners')
  const scopeList = parseList(owners)
  const canCreate = scopeList.length > 0 && (!needsIssuer || !!issuer.trim())

  const issuerLabel =
    traits.issuerInput === 'url'
      ? provider === 'gitlab'
        ? t('scans.ci.trust.gitlabIssuer', 'GitLab URL (issuer)')
        : t('scans.ci.trust.issuer', 'Issuer')
      : traits.issuerInput === 'workspace'
        ? t('scans.ci.setup.workspace', 'Workspace')
        : t('scans.ci.trust.orgId', 'Organization id')

  const create = async () => {
    const existing = findCoveringTrust(trusts.data?.data ?? [], provider, issuer, scopeList)
    if (existing) {
      setSince(Date.now() - 60_000)
      setCreated(existing)
      setReused(true)
      setStep('snippet')
      return
    }
    const body: CITrustConfigRequest = {
      name: `${PROVIDER_LABEL[provider]} · ${scopeList.join(', ')}`.slice(0, 200),
      provider,
      issuer: traits.issuerInput === 'fixed' ? undefined : issuerFor(provider, issuer),
      default_branch: defaultBranch.trim() || 'main',
      enabled: true,
      rules: {
        owners: traits.repositoriesById ? [] : scopeList,
        repositories: traits.repositoriesById ? scopeList : [],
        refs: [],
        environments: [],
        events: [],
        allow_fork_pull_requests: false,
        require_protected_ref: false,
      },
    }
    try {
      const saved = await save({ body })
      setSince(Date.now() - 60_000)
      setCreated(saved)
      setReused(false)
      setStep('snippet')
      toast.success(t('scans.ci.trust.added', 'CI trust added'))
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  const brand = useBrand()
  const snippet = useMemo(
    () =>
      created
        ? snippetFor(provider, {
            apiUrl:
              typeof window === 'undefined'
                ? 'https://openctem.example.com'
                : window.location.origin,
            tenantId: currentTenant?.id ?? '',
            audience: created.audience ?? '',
            defaultBranch: created.default_branch,
            productName: brand.name,
          })
        : '',
    [created, provider, currentTenant, brand.name]
  )

  const stepIndex = STEPS.indexOf(step)
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scans.ci.setup.title', 'Connect a pipeline')}</DialogTitle>
          <DialogDescription>
            {t(
              'scans.ci.setup.description',
              'Pipelines report with their own short-lived identity: nothing secret goes into CI.'
            )}
          </DialogDescription>
          <ol className="flex flex-wrap gap-2 pt-2" aria-label={t('scans.ci.setup.steps', 'Steps')}>
            {STEPS.map((s, i) => (
              <li key={s}>
                <Badge
                  variant={i === stepIndex ? 'default' : i < stepIndex ? 'secondary' : 'outline'}
                  aria-current={i === stepIndex ? 'step' : undefined}
                >
                  {i + 1}. {t(`scans.ci.setup.step.${s}`, s)}
                </Badge>
              </li>
            ))}
          </ol>
        </DialogHeader>
        <DialogBody>
          {step === 'provider' && (
            <div className="grid gap-2 sm:grid-cols-2" role="radiogroup">
              {CI_PROVIDERS.map((p) => (
                <button
                  key={p}
                  type="button"
                  role="radio"
                  aria-checked={provider === p}
                  onClick={() => {
                    setProvider(p)
                    setIssuer('')
                  }}
                  className={cn(
                    'rounded-md border p-3 text-left text-sm transition-colors hover:bg-muted',
                    provider === p && 'border-primary bg-muted'
                  )}
                >
                  {PROVIDER_LABEL[p]}
                </button>
              ))}
            </div>
          )}

          {step === 'organization' && (
            <div className="space-y-4">
              {traits.issuerInput !== 'fixed' && (
                <div className="space-y-1.5">
                  <Label htmlFor="ci-setup-issuer">{issuerLabel}</Label>
                  <Input
                    id="ci-setup-issuer"
                    value={issuer}
                    placeholder={provider === 'gitlab' ? 'https://gitlab.com' : undefined}
                    onChange={(e) => setIssuer(e.target.value)}
                  />
                  {provider === 'gitlab' && (
                    <p className="text-xs text-muted-foreground">
                      {t('scans.ci.trust.gitlabIssuerHint', 'Leave empty for gitlab.com.')}
                    </p>
                  )}
                </div>
              )}
              <div className="space-y-1.5">
                <Label htmlFor="ci-setup-owners">{ownersLabel}</Label>
                <Input
                  id="ci-setup-owners"
                  value={owners}
                  onChange={(e) => setOwners(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  {t(
                    'scans.ci.setup.ownersHint',
                    'Comma separated. Only pipelines of these may report; you can narrow by repository and branch later.'
                  )}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="ci-setup-branch">
                  {t('scans.ci.setup.defaultBranch', 'Default branch')}
                </Label>
                <Input
                  id="ci-setup-branch"
                  value={defaultBranch}
                  onChange={(e) => setDefaultBranch(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  {t(
                    'scans.ci.setup.defaultBranchHint',
                    'Pushes to this branch are scanned in full and become the baseline that pull requests are compared with.'
                  )}
                </p>
              </div>
              {suggestions.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-xs text-muted-foreground">
                    {t('scans.ci.setup.fromApp', 'From your GitHub App installations:')}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {suggestions.map((s) => (
                      <Button
                        key={s}
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          setOwners((cur) => [...new Set([...parseList(cur), s])].join(', '))
                        }
                      >
                        {s}
                      </Button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {step === 'snippet' && (
            <div className="space-y-2">
              {reused && created && (
                <p className="rounded-md border p-3 text-sm" data-testid="ci-setup-reused">
                  {t(
                    'scans.ci.setup.reused',
                    'The trust configuration "{name}" already admits these pipelines, so nothing new was created. Use its snippet in every repository.',
                    { name: created.name ?? '' }
                  )}
                </p>
              )}
              <p className="text-sm text-muted-foreground">
                {provider === 'github'
                  ? t(
                      'scans.ci.setup.snippetHintGithub',
                      'Save this as .github/workflows/openctem.yml in a repository it admits, then push a commit or open a pull request.'
                    )
                  : t(
                      'scans.ci.setup.snippetHint',
                      'Add this to the pipeline of a repository it admits and push a commit or open a pull request.'
                    )}
              </p>
              <pre
                className="overflow-x-auto rounded-md bg-muted p-3 text-xs"
                data-testid="ci-setup-snippet"
              >
                {snippet}
              </pre>
            </div>
          )}

          {step === 'waiting' && (
            <div className="space-y-4" aria-live="polite">
              {firstRun ? (
                <div className="flex items-start gap-2 text-sm">
                  <CircleCheck className="mt-0.5 size-4 text-success" aria-hidden />
                  <div className="space-y-1">
                    <p className="font-medium">
                      {t('scans.ci.setup.received', 'First run received from {repository}', {
                        repository: firstRun.repository ?? '',
                      })}
                    </p>
                    <Link
                      className="text-primary underline-offset-4 hover:underline"
                      href={`/ci-cd?view=runs&run=${encodeURIComponent(firstRun.id ?? '')}`}
                    >
                      {t('scans.ci.setup.openRun', 'Open the run')}
                    </Link>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" aria-hidden />
                  {t('scans.ci.setup.waiting', 'Waiting for the first run…')}
                </div>
              )}
              {!firstRun && lastRefusal && (
                <div className="rounded-md border border-destructive/40 p-3">
                  <p className="mb-2 text-sm font-medium">
                    {t('scans.ci.setup.refused', 'A pipeline was refused')}
                  </p>
                  <RefusalDetail refusal={lastRefusal} />
                </div>
              )}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          {step === 'provider' && (
            <Button onClick={() => setStep('organization')}>
              {t('scans.ci.setup.next', 'Next')}
            </Button>
          )}
          {step === 'organization' && (
            <>
              <Button variant="outline" onClick={() => setStep('provider')}>
                {t('scans.ci.setup.back', 'Back')}
              </Button>
              <Button disabled={!canCreate || isMutating} onClick={create}>
                {t('scans.ci.setup.create', 'Create trust')}
              </Button>
            </>
          )}
          {step === 'snippet' && (
            <>
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
              <Button onClick={() => setStep('waiting')}>
                {t('scans.ci.setup.waitForRun', 'Wait for the first run')}
              </Button>
            </>
          )}
          {step === 'waiting' && (
            <Button variant={firstRun ? 'default' : 'outline'} onClick={onClose}>
              {firstRun ? t('scans.ci.setup.done', 'Done') : t('scans.ci.setup.later', 'Close')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The entry point: the wizard for CI writers, a hint for everyone else. */
export function CISetupEntry({
  canWrite,
  size = 'sm',
}: {
  canWrite: boolean
  size?: 'sm' | 'default'
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  if (!canWrite)
    return (
      <p className="text-sm text-muted-foreground">
        {t('scans.ci.setup.askAdmin', 'Ask an administrator to connect a pipeline.')}
      </p>
    )
  return (
    <>
      <Button size={size} onClick={() => setOpen(true)}>
        {t('scans.ci.setup.open', 'Connect a pipeline')}
      </Button>
      {open && <CISetupWizard open onClose={() => setOpen(false)} />}
    </>
  )
}
