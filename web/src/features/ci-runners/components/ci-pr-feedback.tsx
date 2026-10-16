'use client'

/**
 * Pull request feedback (api RFC-077): the GitHub App installations and the
 * GitLab group connections the platform uses to post the "OpenCTEM gate"
 * check or commit status and one pull or merge request comment. Changes need
 * scans:ci:write (owners and administrators); the API is the authority and
 * never returns a GitLab token.
 */

import { useDocsHref } from '@/context/brand-provider'
import { useState } from 'react'
import { toast } from 'sonner'
import { ExternalLink, GitPullRequest, Plus, Trash2 } from 'lucide-react'
import { GatedButton } from '@/features/shared'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { safeHref } from '@/lib/safe-href'
import { SafeExternalLink } from '@/components/safe-external-link'
import { DOCS } from '@/lib/docs-links'
import {
  useConnectGitLab,
  useGitHubInstallURL,
  useRemoveGitLab,
  useRemoveSCMInstallation,
  useSCMApps,
} from '../api/use-ci'

type Pending = { kind: 'github' | 'gitlab'; id: string; label: string } | null

export function CIPRFeedback({ canWrite }: { canWrite: boolean }) {
  const docsHref = useDocsHref()
  const { t } = useTranslation()
  const { data, isLoading, mutate } = useSCMApps()
  const { trigger: installURL, isMutating: starting } = useGitHubInstallURL()
  const { trigger: removeInstall } = useRemoveSCMInstallation()
  const { trigger: removeGitLab } = useRemoveGitLab()
  const [gitlabOpen, setGitlabOpen] = useState(false)
  const [pending, setPending] = useState<Pending>(null)
  const noWrite = t(
    'scans.ci.noWrite',
    'Only owners and administrators can change CI trust and the gate'
  )

  if (isLoading) return <Skeleton className="h-40 w-full" />
  const github = data?.github
  const installs = data?.data ?? []
  const gitlab = data?.gitlab ?? []

  const install = async () => {
    try {
      const res = await installURL()
      const href = safeHref(res?.url ?? '')
      if (href && href.startsWith('https://')) window.location.assign(href)
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  return (
    <div className="space-y-4" data-testid="ci-pr-feedback">
      <p className="max-w-3xl text-sm text-muted-foreground">
        {t(
          'scans.ci.feedback.description',
          '{product} posts each verdict as the "OpenCTEM gate" check (GitHub) or commit status (GitLab) and keeps one comment on the pull or merge request. The check of a commit takes the strictest verdict of every pipeline on it. Make the check required in branch protection and set its expected source to the {product} app: any other source, such as a workflow\'s own token, could post a check with the same name.'
        )}
      </p>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-base">
              {t('scans.ci.feedback.github', 'GitHub App')}
            </CardTitle>
            <CardDescription>
              {github?.configured ? (
                t(
                  'scans.ci.feedback.githubConfigured',
                  'Install the app on the GitHub organizations whose repositories send results. It can post checks and pull request comments, and read nothing else.'
                )
              ) : (
                <>
                  {t(
                    'scans.ci.feedback.githubMissing',
                    'This deployment has no GitHub App yet. An operator registers it; then install it here.'
                  )}{' '}
                  <SafeExternalLink
                    href={docsHref(DOCS.ci.githubApp)}
                    className="text-primary underline-offset-4 hover:underline"
                  >
                    {t('scans.ci.feedback.githubGuide', 'GitHub App guide')}
                  </SafeExternalLink>
                </>
              )}
            </CardDescription>
          </div>
          {github?.configured && (
            <GatedButton
              allowed={canWrite}
              reason={noWrite}
              size="sm"
              disabled={starting}
              onClick={install}
            >
              <ExternalLink className="size-4" aria-hidden />
              {t('scans.ci.feedback.install', 'Install on GitHub')}
            </GatedButton>
          )}
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {installs.length === 0 ? (
            <p className="text-muted-foreground">
              {t('scans.ci.feedback.noInstalls', 'No installation yet.')}
            </p>
          ) : (
            installs.map((i) => (
              <div
                key={i.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{i.account_login}</span>
                  <Badge variant={i.status === 'active' ? 'outline' : 'secondary'}>
                    {t(`scans.ci.feedback.status.${i.status}`, i.status ?? '')}
                  </Badge>
                  <span className="text-muted-foreground">
                    {i.repository_selection === 'all'
                      ? t('scans.ci.feedback.allRepos', 'all repositories')
                      : t('scans.ci.feedback.selectedRepos', 'selected repositories')}
                  </span>
                </div>
                <GatedButton
                  allowed={canWrite}
                  reason={noWrite}
                  variant="ghost"
                  size="sm"
                  aria-label={t('scans.ci.feedback.unbind', 'Unbind {name}', {
                    name: i.account_login ?? '',
                  })}
                  onClick={() =>
                    setPending({ kind: 'github', id: i.id ?? '', label: i.account_login ?? '' })
                  }
                >
                  <Trash2 className="size-4" aria-hidden />
                </GatedButton>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-base">
              {t('scans.ci.feedback.gitlab', 'GitLab groups')}
            </CardTitle>
            <CardDescription>
              {t(
                'scans.ci.feedback.gitlabDescription',
                'A group access token (Developer role, api scope) lets {product} set the commit status and comment on merge requests of the group. The token is stored encrypted and never shown again.'
              )}
            </CardDescription>
          </div>
          <GatedButton
            allowed={canWrite}
            reason={noWrite}
            size="sm"
            onClick={() => setGitlabOpen(true)}
          >
            <Plus className="size-4" aria-hidden />
            {t('scans.ci.feedback.connectGitlab', 'Connect GitLab group')}
          </GatedButton>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {gitlab.length === 0 ? (
            <p className="text-muted-foreground">
              {t('scans.ci.feedback.noGitlab', 'No GitLab group connected.')}
            </p>
          ) : (
            gitlab.map((c) => (
              <div
                key={c.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <GitPullRequest className="size-4 text-muted-foreground" aria-hidden />
                  <span className="font-medium">
                    {c.host}/{c.group_path}
                  </span>
                  {c.token_expires_at && (
                    <span className="text-muted-foreground">
                      {t('scans.ci.feedback.expires', 'token expires {date}', {
                        date: new Date(c.token_expires_at).toLocaleDateString(),
                      })}
                    </span>
                  )}
                </div>
                <GatedButton
                  allowed={canWrite}
                  reason={noWrite}
                  variant="ghost"
                  size="sm"
                  aria-label={t('scans.ci.feedback.disconnect', 'Disconnect {name}', {
                    name: c.group_path ?? '',
                  })}
                  onClick={() =>
                    setPending({
                      kind: 'gitlab',
                      id: c.id ?? '',
                      label: `${c.host}/${c.group_path}`,
                    })
                  }
                >
                  <Trash2 className="size-4" aria-hidden />
                </GatedButton>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {gitlabOpen && (
        <GitLabDialog onClose={() => setGitlabOpen(false)} onSaved={() => void mutate()} />
      )}

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(o) => !o && setPending(null)}
        destructive
        title={t('scans.ci.feedback.removeTitle', 'Stop posting to {name}?', {
          name: pending?.label ?? '',
        })}
        desc={
          pending?.kind === 'gitlab'
            ? t(
                'scans.ci.feedback.removeGitlab',
                'The stored token is deleted. Runs no longer set the commit status or comment there.'
              )
            : t(
                'scans.ci.feedback.removeGithub',
                'Runs no longer post checks or comments there. The app stays installed on GitHub until someone removes it there.'
              )
        }
        confirmText={t('confirm.delete', 'Delete')}
        handleConfirm={async () => {
          const target = pending
          setPending(null)
          if (!target) return
          try {
            if (target.kind === 'gitlab') await removeGitLab(target.id)
            else await removeInstall(target.id)
            void mutate()
          } catch (e) {
            toast.error(getErrorMessage(e))
          }
        }}
      />
    </div>
  )
}

function GitLabDialog({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation()
  const { trigger, isMutating } = useConnectGitLab()
  const [host, setHost] = useState('')
  const [group, setGroup] = useState('')
  const [token, setToken] = useState('')
  const submit = async () => {
    try {
      await trigger({ host: host.trim(), group: group.trim(), token: token.trim() })
      setToken('')
      toast.success(t('scans.ci.feedback.gitlabConnected', 'GitLab group connected'))
      onSaved()
      onClose()
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('scans.ci.feedback.connectGitlab', 'Connect GitLab group')}</DialogTitle>
          <DialogDescription>
            {t(
              'scans.ci.feedback.gitlabDialog',
              'GitLab must confirm the token is active, has the api scope and belongs to the group. You confirm with your second factor.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="gl-host">{t('scans.ci.feedback.host', 'GitLab host')}</Label>
              <Input
                id="gl-host"
                placeholder="gitlab.com"
                value={host}
                onChange={(e) => setHost(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="gl-group">{t('scans.ci.feedback.group', 'Group path')}</Label>
              <Input
                id="gl-group"
                placeholder="acme/platform"
                value={group}
                onChange={(e) => setGroup(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="gl-token">{t('scans.ci.feedback.token', 'Group access token')}</Label>
              <Input
                id="gl-token"
                type="password"
                autoComplete="off"
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
            </div>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={isMutating || !group.trim() || !token.trim()}>
            {t('scans.ci.feedback.connect', 'Connect')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
