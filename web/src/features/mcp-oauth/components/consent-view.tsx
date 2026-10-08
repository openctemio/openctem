'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  Building2,
  Check,
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
import { useTenant } from '@/context/tenant-provider'

import {
  approveConsent,
  blockedMessage,
  clientKindLabel,
  ConsentError,
  type ConsentRequest,
  denyConsent,
  fetchConsentRequest,
  isRequestId,
} from '../api/consent'

interface ConsentViewProps {
  requestId: string | null
}

/**
 * The consent page of the MCP authorization server (RFC-062 §6). It names
 * the application, where it is published, where the browser goes back to
 * and the organization, so a person can recognize an application pretending
 * to be another one, and lists the access in plain words.
 */
export function ConsentView({ requestId }: ConsentViewProps) {
  const { currentTenant, tenants, loadTenants, switchTeam, isSwitching } = useTenant()
  const [request, setRequest] = useState<ConsentRequest | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [deciding, setDeciding] = useState<'approve' | 'deny' | null>(null)

  const tenantId = currentTenant?.id ?? null
  const validId = isRequestId(requestId)

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
        if (!cancelled)
          setError(e instanceof ConsentError ? e.message : 'This request is no longer available')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [requestId, validId, tenantId])

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
        setError(e instanceof ConsentError ? e.message : 'Could not complete the request')
        setDeciding(null)
      }
    },
    [requestId, validId]
  )

  const grantable = useMemo(() => request?.scopes.filter((s) => s.granted) ?? [], [request])
  const hasWrite = useMemo(() => grantable.some((s) => s.write), [grantable])

  if (!validId) {
    return <Unavailable message="This link is not a valid connection request." />
  }
  if (!tenantId) {
    return (
      <Unavailable message="Choose an organization first: sign in again or pick one from the organization list, then open the link again." />
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
    return <Unavailable message={error ?? 'This request is no longer available.'} />
  }

  const verified = request.verified
  const blocked = request.blocked

  return (
    <Card>
      <CardHeader className="space-y-2">
        <CardTitle className="text-xl break-words">
          Connect {request.client_name} to OpenCTEM?
        </CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-2">
          {verified ? (
            <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
          ) : (
            <ShieldQuestion className="h-4 w-4 text-warning" aria-hidden />
          )}
          <span>{clientKindLabel(request)}</span>
          {!verified && <Badge variant="outline">Unverified</Badge>}
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        <section aria-labelledby="consent-org" className="space-y-2">
          <h2 id="consent-org" className="text-sm font-medium">
            Organization
          </h2>
          <div className="flex items-center gap-2">
            <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
            {tenants.length > 1 ? (
              <Select
                value={tenantId}
                onValueChange={(id) => void switchTeam(id)}
                disabled={isSwitching || deciding !== null}
              >
                <SelectTrigger className="w-full" aria-label="Organization">
                  <SelectValue placeholder={currentTenant?.name ?? 'Organization'} />
                </SelectTrigger>
                <SelectContent>
                  {tenants.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <span className="text-sm">{currentTenant?.name ?? 'Your organization'}</span>
            )}
          </div>
        </section>

        <section aria-labelledby="consent-scopes" className="space-y-2">
          <h2 id="consent-scopes" className="text-sm font-medium">
            It will be able to, as you:
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
                  {s.title}
                  {s.not_allowed && (
                    <span className="ml-2 text-xs no-underline">
                      (not allowed by your organization)
                    </span>
                  )}
                  {s.write && s.granted && (
                    <Badge variant="destructive" className="ml-2">
                      Changes data
                    </Badge>
                  )}
                  {!s.granted && (
                    <span className="sr-only">
                      {' '}
                      (not granted: you do not have this access here)
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">
            It sees only what you can see in this organization, and loses access when you do. You
            can disconnect it at any time.
          </p>
        </section>

        <section aria-labelledby="consent-return" className="space-y-1">
          <h2 id="consent-return" className="text-sm font-medium">
            You will be sent back to
          </h2>
          <p className="break-all font-mono text-sm">{request.redirect_host}</p>
        </section>

        {request.loopback_only && (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Only continue if you started this</AlertTitle>
            <AlertDescription>
              This application runs on your own computer. Any program on it could use the same name.
              Continue only if you just asked {request.client_name} to connect.
            </AlertDescription>
          </Alert>
        )}
        {blocked && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>This application cannot be connected</AlertTitle>
            <AlertDescription>{blockedMessage(blocked)}</AlertDescription>
          </Alert>
        )}
        {!verified && !blocked && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Unverified application</AlertTitle>
            <AlertDescription>
              Nobody vouches for this application&apos;s name. Continue only if you trust where it
              came from.
            </AlertDescription>
          </Alert>
        )}
        {hasWrite && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>This application can change data</AlertTitle>
            <AlertDescription>
              Each change still asks you to confirm it in OpenCTEM.
            </AlertDescription>
          </Alert>
        )}
        {grantable.length === 0 && (
          <Alert>
            <AlertDescription>
              You have none of the access this application asks for in this organization.
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
          Cancel
        </Button>
        <Button
          onClick={() => void decide('approve')}
          disabled={deciding !== null || isSwitching || grantable.length === 0 || !!blocked}
          className="w-full sm:w-auto"
        >
          {deciding === 'approve' && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
          Allow
        </Button>
      </CardFooter>
    </Card>
  )
}

function Unavailable({ message }: { message: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">Cannot connect the application</CardTitle>
        <CardDescription>{message}</CardDescription>
      </CardHeader>
    </Card>
  )
}
