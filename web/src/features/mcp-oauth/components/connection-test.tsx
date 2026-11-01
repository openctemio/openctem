'use client'

import { useState } from 'react'
import { CheckCircle2, CircleDashed, Loader2, XCircle } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { formatRelative } from '@/lib/format-date'

import { fetchMyConnections, type McpConnection } from '../api/connections'

type CheckState = 'ok' | 'fail' | 'idle'

interface Result {
  discovery: CheckState
  device: CheckState
}

/**
 * "Test connection": checks from this browser that the server's sign-in
 * discovery answers (what every client reads first) and that terminal
 * sign-in with a code is offered, then shows the newest connection the
 * person has, so after setting a client up they see it arrive.
 */
export function ConnectionTest() {
  const { t } = useTranslation()
  const [mine, setMine] = useState<McpConnection[]>([])
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<Result | null>(null)

  const run = async () => {
    setRunning(true)
    const next: Result = { discovery: 'fail', device: 'fail' }
    try {
      const prm = await fetch('/.well-known/oauth-protected-resource/api/v1/mcp', {
        credentials: 'omit',
      })
      const as = await fetch('/.well-known/oauth-authorization-server', { credentials: 'omit' })
      if (prm.ok && as.ok) {
        next.discovery = 'ok'
        const doc = (await as.json()) as { device_authorization_endpoint?: string }
        next.device = doc.device_authorization_endpoint ? 'ok' : 'fail'
      }
    } catch {
      // Network failure: both checks stay failed.
    }
    try {
      setMine((await fetchMyConnections()).data ?? [])
    } catch {
      // The connection row stays empty; the two checks above still show.
    }
    setResult(next)
    setRunning(false)
  }

  const newest = [...mine].sort((a, b) => b.created_at.localeCompare(a.created_at))[0]

  return (
    <div className="space-y-3">
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => void run()}
        disabled={running}
      >
        {running && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
        {result ? t('mcp.test.again', 'Test again') : t('mcp.test.run', 'Test connection')}
      </Button>
      {result && (
        <ul className="space-y-1.5 text-sm" role="status">
          <Row
            state={result.discovery}
            text={
              result.discovery === 'ok'
                ? t('mcp.test.discoveryOk', 'The server answers: clients can find how to sign in.')
                : t(
                    'mcp.test.discoveryFail',
                    'The sign-in discovery did not answer from this browser. Check the address and any proxy in between.'
                  )
            }
          />
          <Row
            state={result.device}
            text={
              result.device === 'ok'
                ? t('mcp.test.deviceOk', 'Terminal sign-in with a code is offered.')
                : t('mcp.test.deviceFail', 'Terminal sign-in with a code is not offered.')
            }
          />
          <Row
            state={newest ? 'ok' : 'idle'}
            text={
              newest
                ? t('mcp.test.latest', 'Your newest connection: {client}, connected {when}.', {
                    client: newest.client_name,
                    when: formatRelative(newest.created_at),
                  })
                : t(
                    'mcp.test.none',
                    'No assistant is connected yet. Set one up, sign in, then test again.'
                  )
            }
          />
        </ul>
      )}
    </div>
  )
}

function Row({ state, text }: { state: CheckState; text: string }) {
  const Icon = state === 'ok' ? CheckCircle2 : state === 'fail' ? XCircle : CircleDashed
  const tone =
    state === 'ok'
      ? 'text-success'
      : state === 'fail'
        ? 'text-destructive'
        : 'text-muted-foreground'
  return (
    <li className="flex items-start gap-2">
      <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${tone}`} aria-hidden />
      <span>{text}</span>
    </li>
  )
}
