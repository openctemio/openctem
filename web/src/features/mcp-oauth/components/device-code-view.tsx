'use client'

import { useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { AlertTriangle, Loader2, Terminal } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'

import { ConsentError, enterDeviceCode } from '../api/consent'
import { formatUserCodeInput, normalizeUserCode } from '../lib/device-code'

/**
 * /oauth/device: the person types the code a terminal shows (an AI
 * assistant signing in from an SSH session, a container or another
 * machine). The code makes the request theirs; the consent page then shows
 * where the terminal asked from and lets them decide. There is deliberately
 * no link that fills the code in: typing it is what tells a person's own
 * sign-in from one someone asks them to approve.
 */
export function DeviceCodeView() {
  const { t } = useTranslation()
  const router = useRouter()
  const { currentTenant } = useTenant()
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const normalized = normalizeUserCode(code)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!normalized) {
      setError(t('mcp.device.malformed', 'Enter the 8 characters your terminal shows.'))
      return
    }
    setBusy(true)
    setError(null)
    try {
      const id = await enterDeviceCode(normalized)
      router.push(`/oauth/consent?request=${encodeURIComponent(id)}`)
    } catch (err: unknown) {
      const status = err instanceof ConsentError ? err.status : 0
      if (status === 429) {
        setError(t('mcp.device.tooMany', 'Too many attempts. Wait a minute and try again.'))
      } else if (status === 403) {
        setError(
          t(
            'mcp.device.disabled',
            'Your organization does not allow signing a terminal in with a code.'
          )
        )
      } else {
        setError(
          t(
            'mcp.device.invalid',
            'This code is not valid. Check the code your terminal shows; a code works once and expires after 10 minutes.'
          )
        )
      }
      setBusy(false)
    }
  }

  return (
    <Card>
      <form onSubmit={(e) => void submit(e)} noValidate>
        <CardHeader className="space-y-2">
          <CardTitle className="flex items-center gap-2 text-xl">
            <Terminal className="h-5 w-5 text-muted-foreground" aria-hidden />
            {t('mcp.device.title', 'Connect a terminal')}
          </CardTitle>
          <CardDescription>
            {t(
              'mcp.device.description',
              'Enter the code your AI assistant shows in its terminal. You will see where the request came from before anything is connected.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 pt-2">
          <div className="space-y-2">
            <Label htmlFor="device-user-code">{t('mcp.device.codeLabel', 'Code')}</Label>
            <Input
              id="device-user-code"
              value={code}
              onChange={(e) => setCode(formatUserCodeInput(e.target.value))}
              placeholder="XXXX-XXXX"
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              inputMode="text"
              maxLength={9}
              className="font-mono text-lg tracking-widest"
              aria-describedby="device-user-code-hint"
              aria-invalid={error ? true : undefined}
              disabled={busy}
              autoFocus
            />
            <p id="device-user-code-hint" className="text-xs text-muted-foreground">
              {currentTenant?.name
                ? t('mcp.device.orgHint', 'It will connect to {org}, as you.', {
                    org: currentTenant.name,
                  })
                : t(
                    'mcp.device.noOrgHint',
                    'It will connect to your current organization, as you.'
                  )}
            </p>
          </div>
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>
              {t('mcp.device.warningTitle', 'Only enter a code you asked for')}
            </AlertTitle>
            <AlertDescription>
              {t(
                'mcp.device.warning',
                'Enter a code only if you just started the sign-in yourself, on a machine you control. Never enter a code someone sent you or asked you to type.'
              )}
            </AlertDescription>
          </Alert>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
        <CardFooter className="flex justify-end">
          <Button type="submit" disabled={busy || !normalized} className="w-full sm:w-auto">
            {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
            {t('mcp.device.continue', 'Continue')}
          </Button>
        </CardFooter>
      </form>
    </Card>
  )
}
