'use client'

import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, Loader2, XCircle } from 'lucide-react'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTenant } from '@/context/tenant-provider'

import { decideConfirmation, fetchConfirmation, type McpConfirmation } from '../api/confirmations'
import { isRequestId } from '../api/consent'

/**
 * Confirms a change an AI application asked to make (RFC-062 §10). The
 * page is OpenCTEM's, outside the application: the agent cannot answer it.
 * It shows the exact action as the server describes it; approving lets the
 * application run it once within five minutes.
 */
export function ConfirmView({ id }: { id: string | null }) {
  const { currentTenant } = useTenant()
  const [item, setItem] = useState<McpConfirmation | null | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<'approved' | 'denied' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const valid = isRequestId(id)
  const tenantId = currentTenant?.id

  const load = useCallback(async () => {
    if (!valid || !tenantId) return
    try {
      setItem(await fetchConfirmation(id))
    } catch {
      setError('Could not load the request')
      setItem(null)
    }
  }, [id, valid, tenantId])

  useEffect(() => {
    void load()
  }, [load])

  const decide = async (approve: boolean) => {
    if (!valid) return
    setBusy(true)
    setError(null)
    const ok = await decideConfirmation(id, approve)
    setBusy(false)
    if (ok) setDone(approve ? 'approved' : 'denied')
    else setError('This request is no longer open (expired or already answered).')
  }

  if (!valid)
    return <Message title="Nothing to confirm" text="This link is not a valid confirmation." />
  if (item === undefined && !error) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-2/3" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-20 w-full" />
        </CardContent>
      </Card>
    )
  }
  if (!item) {
    return (
      <Message
        title="Nothing to confirm"
        text={
          error ??
          `No such request for you in ${currentTenant?.name ?? 'this organization'}. Make sure you are signed in as the person who connected the application, in the same organization.`
        }
      />
    )
  }
  if (done) {
    return (
      <Message
        title={done === 'approved' ? 'Confirmed' : 'Refused'}
        text={
          done === 'approved'
            ? `Go back to ${item.client_name}: it can now make this change once, within five minutes.`
            : `${item.client_name} will not make this change.`
        }
        icon={done === 'approved' ? 'ok' : 'no'}
      />
    )
  }
  const open = item.status === 'pending' && !item.expired

  return (
    <Card>
      <CardHeader className="space-y-2">
        <CardTitle className="text-xl break-words">
          {item.client_name} wants to make a change
        </CardTitle>
        <CardDescription>
          Check exactly what it will do. It acts as you, in{' '}
          {currentTenant?.name ?? 'this organization'}.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <pre className="bg-muted max-h-96 overflow-auto rounded-md p-4 text-sm whitespace-pre-wrap break-words">
          {item.summary}
        </pre>
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Only confirm if you asked the application to do this. An application can be tricked by
            content it reads.
          </AlertDescription>
        </Alert>
        {!open && (
          <Alert variant="destructive">
            <AlertDescription>
              {item.expired ? 'This request expired.' : `This request was already ${item.status}.`}
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
          disabled={busy || !open}
          onClick={() => void decide(false)}
          className="w-full sm:w-auto"
        >
          Refuse
        </Button>
        <Button
          disabled={busy || !open}
          onClick={() => void decide(true)}
          className="w-full sm:w-auto"
        >
          {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
          Confirm
        </Button>
      </CardFooter>
    </Card>
  )
}

function Message({ title, text, icon }: { title: string; text: string; icon?: 'ok' | 'no' }) {
  return (
    <Card>
      <CardHeader className="space-y-2">
        <CardTitle className="flex items-center gap-2 text-xl">
          {icon === 'ok' && <CheckCircle2 className="text-success h-5 w-5" aria-hidden />}
          {icon === 'no' && <XCircle className="text-muted-foreground h-5 w-5" aria-hidden />}
          {title}
        </CardTitle>
        <CardDescription>{text}</CardDescription>
      </CardHeader>
    </Card>
  )
}
