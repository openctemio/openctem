'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  Building2,
  Check,
  CheckCircle2,
  Loader2,
  ShieldCheck,
  ShieldQuestion,
  X,
} from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import { allowPublisher, requestPublisherAccess } from '../api/access-requests'
import {
  approveConsent,
  ConsentError,
  type ConsentRequest,
  denyConsent,
  fetchConsentRequest,
  isRequestId,
} from '../api/consent'
import { useMcpLabels } from '../lib/use-mcp-labels'

interface ConsentViewProps {
  requestId: string | null
}

/**
 * The consent page of the MCP authorization server (RFC-062 §6). It names
 * the application, where it is published, where the browser goes back to
 * and the organization, so a person can recognize an application pretending
 * to be another one, and lists the access in plain words. When the
 * organization has not approved the application's publisher, a member can
 * ask an administrator, and someone who may change the policy can approve
 * the publisher right here.
 */
export function ConsentView({ requestId }: ConsentViewProps) {
  const { t } = useTranslation()
  const { scopeTitle, clientKind, blockedMessage } = useMcpLabels()
  const { currentTenant, tenants, loadTenants, switchTeam, isSwitching } = useTenant()
  const [request, setRequest] = useState<ConsentRequest | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [deciding, setDeciding] = useState<'approve' | 'deny' | null>(null)
  const [asking, setAsking] = useState(false)
  const [asked, setAsked] = useState(false)
  const [confirmAllow, setConfirmAllow] = useState(false)
  const [allowing, setAllowing] = useState(false)
  const [reload, setReload] = useState(0)

  const tenantId = currentTenant?.id ?? null
  const validId = isRequestId(requestId)
  const unavailable = t('mcp.consent.unavailable', 'This request is no longer available.')

  useEffect(() => {
    loadTenants()
  }, [loadTenants])

  // Read the request in the session's current organization; again after a
  // switch, since what is granted depends on the organization.
  useEffect(() => {
    if (!validId || !tenantId) {
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    setError(null)
    fetchConsentRequest(requestId)
      .then((r) => {
        if (!cancelled) setRequest(r)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof ConsentError && e.message ? e.message : unavailable)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [requestId, validId, tenantId, reload, unavailable])

  const decide = useCallback(
    async (decision: 'approve' | 'deny') => {
      if (!validId) return
      setDeciding(decision)
      setError(null)
      try {
        const to =
          decision === 'approve' ? await approveConsent(requestId) : await denyConsent(requestId)
        window.location.assign(to)
      } catch (e: unknown) {
        setError(
          e instanceof ConsentError && e.message
            ? e.message
            : t('mcp.consent.failed', 'Could not complete the request.')
        )
        setDeciding(null)
      }
    },
    [requestId, validId, t]
  )

  const ask = async () => {
    if (!validId) return
    setAsking(true)
    setError(null)
    try {
      await requestPublisherAccess(requestId)
      setAsked(true)
    } catch (e: unknown) {
      setError(getErrorMessage(e, t('mcp.consent.requestFailed', 'Could not send the request.')))
    } finally {
      setAsking(false)
    }
  }

  const allow = async () => {
    if (!validId) return
    setAllowing(true)
    setError(null)
    try {
      await allowPublisher(requestId)
      setConfirmAllow(false)
      setReload((n) => n + 1)
    } catch (e: unknown) {
      setError(getErrorMessage(e, t('mcp.consent.allowFailed', 'Could not approve the publisher.')))
    } finally {
      setAllowing(false)
    }
  }

  const grantable = useMemo(() => request?.scopes.filter((s) => s.granted) ?? [], [request])
  const hasWrite = useMemo(() => grantable.some((s) => s.write), [grantable])

  if (!validId) {
    return (
      <Unavailable
        message={t('mcp.consent.invalidLink', 'This link is not a valid connection request.')}
      />
    )
  }
  if (!tenantId) {
    return (
      <Unavailable
        message={t(
          'mcp.consent.noOrganization',
          'Choose an organization first: sign in again or pick one from the organization list, then open the link again.'
        )}
      />
    )
  }
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-2/3" />
          <Skeleton className="h-4 w-1/2" />
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
          <Skeleton className="h-4 w-4/6" />
        </CardContent>
      </Card>
    )
  }
  if (!request) {
    return <Unavailable message={error ?? unavailable} />
  }

  const verified = request.verified
  const blocked = request.blocked
  const host = request.client_host
  const orgName = currentTenant?.name ?? t('mcp.consent.yourOrganization', 'your organization')
  const requested = asked || !!request.access_requested

  return (
    <Card>
      <CardHeader className="space-y-2">
        <CardTitle className="text-xl break-words">
          {t('mcp.consent.title', 'Connect {client} to {product}?', {
            client: request.client_name,
          })}
        </CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-2">
          {verified ? (
            <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
          ) : (
            <ShieldQuestion className="h-4 w-4 text-warning" aria-hidden />
          )}
          <span>{clientKind(request.client_kind, host)}</span>
          {!verified && <Badge variant="outline">{t('mcp.client.unverified', 'Unverified')}</Badge>}
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        <section aria-labelledby="consent-org" className="space-y-2">
          <h2 id="consent-org" className="text-sm font-medium">
            {t('mcp.consent.organization', 'Organization')}
          </h2>
          <div className="flex items-center gap-2">
            <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
            {tenants.length > 1 ? (
              <Select
                value={tenantId}
                onValueChange={(id) => void switchTeam(id)}
                disabled={isSwitching || deciding !== null}
              >
                <SelectTrigger
                  className="w-full"
                  aria-label={t('mcp.consent.organization', 'Organization')}
                >
                  <SelectValue placeholder={orgName} />
                </SelectTrigger>
                <SelectContent>
                  {tenants.map((tn) => (
                    <SelectItem key={tn.id} value={tn.id}>
                      {tn.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <span className="text-sm">{orgName}</span>
            )}
          </div>
        </section>

        <section aria-labelledby="consent-scopes" className="space-y-2">
          <h2 id="consent-scopes" className="text-sm font-medium">
            {t('mcp.consent.scopesHeading', 'It will be able to, as you:')}
          </h2>
          <ul className="space-y-1.5">
            {request.scopes.map((s) => (
              <li key={s.scope} className="flex items-start gap-2 text-sm">
                {s.granted ? (
                  <Check className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
                ) : (
                  <X className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                )}
                <span className={s.granted ? undefined : 'text-muted-foreground line-through'}>
                  {scopeTitle(s.scope, s.title)}
                  {s.not_allowed && (
                    <span className="ml-2 text-xs no-underline">
                      {t('mcp.consent.notAllowed', '(not allowed by your organization)')}
                    </span>
                  )}
                  {s.write && s.granted && (
                    <Badge variant="destructive" className="ml-2">
                      {t('mcp.consent.changesData', 'Changes data')}
                    </Badge>
                  )}
                  {!s.granted && (
                    <span className="sr-only">
                      {' '}
                      {t(
                        'mcp.consent.notGranted',
                        '(not granted: you do not have this access here)'
                      )}
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">
            {t(
              'mcp.consent.seesWhatYouSee',
              'It sees only what you can see in this organization, and loses access when you do. You can disconnect it at any time.'
            )}
          </p>
        </section>

        <section aria-labelledby="consent-return" className="space-y-1">
          <h2 id="consent-return" className="text-sm font-medium">
            {t('mcp.consent.returnTo', 'You will be sent back to')}
          </h2>
          <p className="break-all font-mono text-sm">{request.redirect_host}</p>
        </section>

        {request.loopback_only && (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>
              {t('mcp.consent.loopbackTitle', 'Only continue if you started this')}
            </AlertTitle>
            <AlertDescription>
              {t(
                'mcp.consent.loopbackDesc',
                'This application runs on your own computer. Any program on it could use the same name. Continue only if you just asked {client} to connect.',
                { client: request.client_name }
              )}
            </AlertDescription>
          </Alert>
        )}
        {blocked && (
          <Alert variant={request.requestable ? 'default' : 'destructive'}>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>
              {blocked === 'mcp_disabled'
                ? t('mcp.consent.blockedDisabledTitle', 'AI assistants are turned off')
                : t(
                    'mcp.consent.blockedTitle',
                    'Your organization has not approved this application'
                  )}
            </AlertTitle>
            <AlertDescription className="space-y-3">
              <p>{blockedMessage(blocked, request.client_kind, host)}</p>
              {request.requestable && request.can_allow && (
                <Button size="sm" onClick={() => setConfirmAllow(true)} disabled={allowing}>
                  <ShieldCheck className="mr-2 h-4 w-4" aria-hidden />
                  {t('mcp.consent.allowPublisher', 'Allow {host} for {org}', {
                    host: host ?? '',
                    org: orgName,
                  })}
                </Button>
              )}
              {request.requestable &&
                !request.can_allow &&
                (requested ? (
                  <p className="flex items-start gap-2 font-medium" role="status">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
                    {t(
                      'mcp.consent.requestSent',
                      'Request sent. Your administrators were notified; connect again after they approve it.'
                    )}
                  </p>
                ) : (
                  <Button size="sm" variant="outline" onClick={() => void ask()} disabled={asking}>
                    {asking && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
                    {t('mcp.consent.requestAccess', 'Request access')}
                  </Button>
                ))}
            </AlertDescription>
          </Alert>
        )}
        {!verified && !blocked && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>{t('mcp.consent.unverifiedTitle', 'Unverified application')}</AlertTitle>
            <AlertDescription>
              {t(
                'mcp.consent.unverifiedDesc',
                'Nobody vouches for this application’s name. Continue only if you trust where it came from.'
              )}
            </AlertDescription>
          </Alert>
        )}
        {hasWrite && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>
              {t('mcp.consent.writeTitle', 'This application can change data')}
            </AlertTitle>
            <AlertDescription>
              {t(
                'mcp.consent.confirmEach',
                'Each change still asks you to confirm it in {product}.'
              )}
            </AlertDescription>
          </Alert>
        )}
        {grantable.length === 0 && (
          <Alert>
            <AlertDescription>
              {t(
                'mcp.consent.nothingToGrant',
                'You have none of the access this application asks for in this organization.'
              )}
            </AlertDescription>
          </Alert>
        )}
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </CardContent>

      <CardFooter className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <Button
          variant="outline"
          onClick={() => void decide('deny')}
          disabled={deciding !== null || isSwitching}
          className="w-full sm:w-auto"
        >
          {deciding === 'deny' && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
          {t('mcp.common.cancel', 'Cancel')}
        </Button>
        <Button
          onClick={() => void decide('approve')}
          disabled={deciding !== null || isSwitching || grantable.length === 0 || !!blocked}
          className="w-full sm:w-auto"
        >
          {deciding === 'approve' && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
          {t('mcp.consent.allow', 'Allow')}
        </Button>
      </CardFooter>

      <ConfirmDialog
        open={confirmAllow}
        onOpenChange={(v) => !v && !allowing && setConfirmAllow(false)}
        title={t('mcp.requests.approveTitle', 'Approve applications published by {host}?', {
          host: host ?? '',
        })}
        desc={t(
          'mcp.requests.approveDesc',
          'Every member can then connect applications whose identity is published on {host}. Each person still approves what it may do, and it never sees more than they can. You can remove the publisher at any time.',
          { host: host ?? '' }
        )}
        confirmText={t('mcp.requests.approve', 'Approve')}
        isLoading={allowing}
        handleConfirm={() => allow()}
      />
    </Card>
  )
}

function Unavailable({ message }: { message: string }) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">
          {t('mcp.consent.cannotConnect', 'Cannot connect the application')}
        </CardTitle>
        <CardDescription>{message}</CardDescription>
      </CardHeader>
    </Card>
  )
}
