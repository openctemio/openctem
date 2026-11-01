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
  Terminal,
  X,
} from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
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
  const [fullData, setFullData] = useState(false)
  // A terminal sign-in has nowhere to send the browser: the page says so.
  const [done, setDone] = useState<'approved' | 'denied' | null>(null)

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
    // The choice never carries over to another organization or request.
    setFullData(false)
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
          decision === 'approve'
            ? await approveConsent(requestId, fullData)
            : await denyConsent(requestId)
        if (to === '') {
          setDone(decision === 'approve' ? 'approved' : 'denied')
          setDeciding(null)
          return
        }
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
    [requestId, validId, fullData, t]
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
  if (done) {
    return <TerminalDone approved={done === 'approved'} client={request.client_name} />
  }

  const verified = request.verified
  const blocked = request.blocked
  const host = request.client_host
  const orgName = currentTenant?.name ?? t('mcp.consent.yourOrganization', 'your organization')
  const requested = asked || !!request.access_requested
  const device = request.flow === 'device'

  return (
    <Card>
      <CardHeader className="space-y-2">
        <CardTitle className="text-xl break-words">
          {t('mcp.consent.title', 'Connect {client} to {product}?', {
            client: request.client_name,
          })}
        </CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-2">
          {device ? (
            <>
              <Terminal className="h-4 w-4 text-warning" aria-hidden />
              <span>{t('mcp.consent.device.kind', 'A terminal asked to connect with a code')}</span>
            </>
          ) : (
            <>
              {verified ? (
                <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
              ) : (
                <ShieldQuestion className="h-4 w-4 text-warning" aria-hidden />
              )}
              <span>{clientKind(request.client_kind, host)}</span>
              {!verified && (
                <Badge variant="outline">{t('mcp.client.unverified', 'Unverified')}</Badge>
              )}
            </>
          )}
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

        {request.full_data_available && (
          <section aria-labelledby="consent-full-data" className="space-y-2">
            <div className="flex items-start gap-3 rounded-md border p-3">
              <Checkbox
                id="consent-full-data-option"
                checked={fullData}
                onCheckedChange={(v) => setFullData(v === true)}
                disabled={deciding !== null}
                className="mt-0.5"
                aria-describedby="consent-full-data-desc"
              />
              <div className="space-y-1">
                <label
                  id="consent-full-data"
                  htmlFor="consent-full-data-option"
                  className="text-sm font-medium"
                >
                  {t('mcp.consent.fullData', 'Allow access to all organization data')}
                </label>
                <p id="consent-full-data-desc" className="text-xs text-muted-foreground">
                  {t(
                    'mcp.consent.fullDataDesc',
                    'Without this, it sees only the assets your own groups give you. With it, it sees every asset and finding in this organization, as an administrator does. You will be asked to confirm your identity. It stops seeing everything as soon as your role loses this access, and the connection ends sooner than usual (7 days).'
                  )}
                </p>
              </div>
            </div>
          </section>
        )}

        {device ? (
          <DeviceOrigin request={request} />
        ) : (
          <section aria-labelledby="consent-return" className="space-y-1">
            <h2 id="consent-return" className="text-sm font-medium">
              {t('mcp.consent.returnTo', 'You will be sent back to')}
            </h2>
            <p className="break-all font-mono text-sm">{request.redirect_host}</p>
          </section>
        )}
        {device && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>
              {t('mcp.consent.device.warningTitle', 'Did you start this sign-in yourself?')}
            </AlertTitle>
            <AlertDescription>
              {t(
                'mcp.consent.device.warning',
                'Allow only if you typed this code from your own terminal in the last few minutes. If someone sent you the code or asked you to enter it, choose Cancel: allowing would give them your access.'
              )}
            </AlertDescription>
          </Alert>
        )}

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
        {!verified && !blocked && !device && (
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

/**
 * Where a terminal sign-in came from: the address and program that asked,
 * when, and whether this browser is on the same address. A request made
 * from somewhere the person does not recognise is the sign of a code they
 * were talked into entering.
 */
function DeviceOrigin({ request }: { request: ConsentRequest }) {
  const { t } = useTranslation()
  const at = request.requested_at ? new Date(request.requested_at) : null
  return (
    <section aria-labelledby="consent-device-origin" className="space-y-2">
      <h2 id="consent-device-origin" className="text-sm font-medium">
        {t('mcp.consent.device.origin', 'Where the request came from')}
      </h2>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t('mcp.consent.device.address', 'Address')}</dt>
        <dd className="break-all font-mono">
          {request.requester_ip || t('mcp.consent.device.unknown', 'Unknown')}
        </dd>
        <dt className="text-muted-foreground">{t('mcp.consent.device.program', 'Program')}</dt>
        <dd className="break-all font-mono text-xs leading-5">
          {request.requester_user_agent || t('mcp.consent.device.unknown', 'Unknown')}
        </dd>
        {at && (
          <>
            <dt className="text-muted-foreground">{t('mcp.consent.device.when', 'Asked at')}</dt>
            <dd>
              <time dateTime={request.requested_at}>{at.toLocaleString()}</time>
            </dd>
          </>
        )}
        <dt className="text-muted-foreground">
          {t('mcp.consent.device.yourAddress', 'Your address')}
        </dt>
        <dd className="flex flex-wrap items-center gap-2">
          <span className="break-all font-mono">{request.your_ip || '-'}</span>
          {request.same_address ? (
            <Badge variant="secondary">{t('mcp.consent.device.same', 'Same address')}</Badge>
          ) : (
            <Badge variant="outline">
              {t('mcp.consent.device.different', 'Different address')}
            </Badge>
          )}
        </dd>
      </dl>
      {!request.same_address && (
        <p className="text-xs text-muted-foreground">
          {t(
            'mcp.consent.device.differentHint',
            'Expected when the terminal runs on a server or another network. Check that the address is one you know.'
          )}
        </p>
      )}
    </section>
  )
}

function TerminalDone({ approved, client }: { approved: boolean; client: string }) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader className="space-y-2">
        <CardTitle className="flex items-center gap-2 text-xl">
          {approved ? (
            <CheckCircle2 className="h-5 w-5 text-success" aria-hidden />
          ) : (
            <X className="h-5 w-5 text-muted-foreground" aria-hidden />
          )}
          {approved
            ? t('mcp.consent.device.doneTitle', '{client} is connected', { client })
            : t('mcp.consent.device.refusedTitle', 'Not connected')}
        </CardTitle>
        <CardDescription role="status">
          {approved
            ? t(
                'mcp.consent.device.doneDesc',
                'Go back to your terminal: it picks the connection up within a few seconds. You can close this page, and disconnect it any time under Connected applications.'
              )
            : t(
                'mcp.consent.device.refusedDesc',
                'Nothing was shared. The terminal is told the request was refused. You can close this page.'
              )}
        </CardDescription>
      </CardHeader>
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
