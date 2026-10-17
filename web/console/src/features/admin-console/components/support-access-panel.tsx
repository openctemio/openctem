'use client'

/**
 * Console › Support access (api RFC-063): the live grants that name the
 * caller, and the support session opened from one. The session id lives in
 * this component and the page URL only (never browser storage), so a reload
 * can come back to an open session while its grant is live. The server is the
 * boundary: it checks and audits every read.
 */

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { AlertCircle, Eye, LifeBuoy, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState } from '@/features/shared'
import { formatSupportTime } from '@/features/support-access/lib/format'
import { replaceUrlSearch, useUrlParam } from '@/hooks/use-url-param'
import type { AdminSupportGrant } from '@/lib/api/generated'

import {
  endSupportSession,
  isSupportAccessEnded,
  openSupportSession,
  useAdminSupportGrants,
} from '../api/use-admin-support'
import { SupportSessionView, type SupportSessionState } from './support-session-view'

const REASON_MAX = 500

function writeSessionUrl(session: SupportSessionState | null) {
  const params = new URLSearchParams(window.location.search)
  if (session) {
    params.set('session', session.id)
    params.set('grant', session.grantId)
  } else {
    params.delete('session')
    params.delete('grant')
  }
  replaceUrlSearch(params)
}

function stateFor(grant: AdminSupportGrant, sessionId: string): SupportSessionState {
  return {
    id: sessionId,
    grantId: grant.id ?? '',
    tenantName: grant.tenant_name || grant.tenant_id || '',
    scopes: grant.scopes ?? [],
    expiresAt: grant.expires_at ?? '',
  }
}

function OpenSessionDialog({
  grant,
  onClose,
  onOpened,
}: {
  grant: AdminSupportGrant | null
  onClose: () => void
  onOpened: (s: SupportSessionState) => void
}) {
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (!grant?.id) return
    setBusy(true)
    setError(null)
    try {
      const s = await openSupportSession(grant.id, reason.trim() || undefined)
      setReason('')
      onOpened({
        ...stateFor(grant, s.id ?? ''),
        scopes: s.scopes ?? grant.scopes ?? [],
        expiresAt: s.expires_at ?? grant.expires_at ?? '',
      })
    } catch (err) {
      setError(
        isSupportAccessEnded(err)
          ? t('admin.support.grantGone', 'This access is no longer available.')
          : err instanceof Error
            ? err.message
            : t('admin.support.openFailed', 'The session could not be opened.')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open={grant !== null}
      onOpenChange={(o) => {
        if (!o) {
          setReason('')
          setError(null)
          onClose()
        }
      }}
    >
      <DialogContent size="md">
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t('admin.support.openTitle', 'Open a support session')}</DialogTitle>
            <DialogDescription>
              {t(
                'admin.support.openDescription',
                'You will read {org}’s data read-only. The owners are emailed, every member sees a banner, and every page you open is recorded in their audit log.',
                { org: grant?.tenant_name || grant?.tenant_id || '' }
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <div className="space-y-2">
              <Label htmlFor="support-session-reason">
                {t('admin.support.sessionReason', 'What you will look at (optional)')}
              </Label>
              <Textarea
                id="support-session-reason"
                rows={3}
                maxLength={REASON_MAX}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={busy}>
              {busy && <Loader2 className="size-4 animate-spin" aria-hidden="true" />}
              {t('admin.support.open', 'Open support session')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

export function SupportAccessPanel({ canSupport }: { canSupport: boolean }) {
  const { t, locale } = useTranslation()
  const { data, error, isLoading, mutate } = useAdminSupportGrants()
  const [opening, setOpening] = useState<AdminSupportGrant | null>(null)
  const [session, setSession] = useState<SupportSessionState | null>(null)
  const [ended, setEnded] = useState(false)
  const [ending, setEnding] = useState(false)
  const urlSession = useUrlParam('session')
  const urlGrant = useUrlParam('grant')
  const grants = data?.data ?? []

  // Come back to the session named in the URL while its grant is still live.
  useEffect(() => {
    if (session || !urlSession || !urlGrant || !data) return
    const g = (data.data ?? []).find((x) => x.id === urlGrant)
    if (g) setSession(stateFor(g, urlSession))
    else writeSessionUrl(null)
  }, [data, session, urlSession, urlGrant])

  const start = useCallback((s: SupportSessionState) => {
    setOpening(null)
    setEnded(false)
    setSession(s)
    writeSessionUrl(s)
  }, [])

  const leave = useCallback(() => {
    setSession(null)
    writeSessionUrl(null)
    void mutate()
  }, [mutate])

  // A read said the access ended (revoked, expired, or ended elsewhere).
  const onEnded = useCallback(() => {
    setEnded(true)
    leave()
  }, [leave])

  async function endNow() {
    if (!session) return
    setEnding(true)
    try {
      await endSupportSession(session.id)
      toast.success(t('admin.support.endedByYou', 'Support session ended'))
    } catch (err) {
      if (!isSupportAccessEnded(err)) {
        toast.error(
          err instanceof Error
            ? err.message
            : t('admin.support.endFailed', 'Could not end the session')
        )
        setEnding(false)
        return
      }
    }
    setEnding(false)
    setEnded(false)
    leave()
  }

  if (session) {
    return <SupportSessionView session={session} onEnd={endNow} onEnded={onEnded} ending={ending} />
  }

  return (
    <div className="space-y-4">
      {ended && (
        <Alert data-testid="support-access-ended">
          <AlertCircle className="size-4" />
          <AlertTitle>{t('admin.support.endedTitle', 'Access ended')}</AlertTitle>
          <AlertDescription>
            {t(
              'admin.support.endedBody',
              'The organization revoked the access, it expired, or the session was ended elsewhere. Nothing more can be read.'
            )}
          </AlertDescription>
        </Alert>
      )}
      {!canSupport && (
        <Alert>
          <AlertCircle className="size-4" />
          <AlertDescription>
            {t(
              'admin.support.readonlyNote',
              'Support sessions need an operations or super administrator.'
            )}
          </AlertDescription>
        </Alert>
      )}
      {error ? (
        <ErrorState
          title={t('admin.support.grantsFailed', 'Support grants could not be loaded')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : isLoading ? (
        <Skeleton className="h-32 w-full" />
      ) : grants.length === 0 ? (
        <EmptyState
          icon={LifeBuoy}
          card
          title={t('admin.support.empty', 'No organization has granted you access')}
          description={t(
            'admin.support.emptyHint',
            'An organization owner grants access under Settings › Support access, naming your email.'
          )}
        />
      ) : (
        <ul className="space-y-3">
          {grants.map((g) => (
            <li
              key={g.id}
              data-testid="support-grant"
              className="flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-start sm:justify-between"
            >
              <div className="min-w-0 space-y-1">
                <p className="flex flex-wrap items-center gap-2 font-medium break-words">
                  {g.tenant_name || g.tenant_id}
                  {g.open_session && (
                    <Badge variant="outline" className="border-warning/50 text-warning">
                      <Eye className="size-3" aria-hidden="true" />
                      {t('admin.support.sessionOpen', 'Session open')}
                    </Badge>
                  )}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {(g.scopes ?? []).map((s) => (
                    <Badge key={s} variant="secondary">
                      {t(`admin.support.scope.${s}`, s)}
                    </Badge>
                  ))}
                </div>
                <p className="text-sm break-words">{g.reason}</p>
                <p className="text-xs text-muted-foreground">
                  {t('admin.support.until', 'Until {time}', {
                    time: formatSupportTime(g.expires_at, locale),
                  })}
                  {g.case_ref
                    ? ` · ${t('admin.support.case', 'case {ref}', { ref: g.case_ref })}`
                    : ''}
                </p>
              </div>
              {canSupport && (
                <Button className="shrink-0 self-start" onClick={() => setOpening(g)}>
                  {t('admin.support.open', 'Open support session')}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      <OpenSessionDialog grant={opening} onClose={() => setOpening(null)} onOpened={start} />
    </div>
  )
}
