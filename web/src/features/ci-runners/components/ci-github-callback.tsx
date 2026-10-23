'use client'

/**
 * GitHub's setup redirect after the OpenCTEM GitHub App is installed
 * (api RFC-077). The query carries installation_id, the OAuth code of the
 * person who installed it and the state the console issued; the API binds
 * the installation only when the state is this person's for this
 * organization and their own GitHub authorization reaches the installation.
 */

import { useEffect, useRef, useState } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import Link from '@/components/link'
import { CheckCircle2, ShieldX } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useBrand } from '@/context/brand-provider'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCompleteGitHubInstall } from '../api/use-ci'

type State =
  | { kind: 'working' }
  | { kind: 'done'; account: string }
  | { kind: 'requested' }
  | { kind: 'error'; message: string }

export function CIGitHubCallback() {
  const { t } = useTranslation()
  const params = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()
  const brand = useBrand()
  const { trigger } = useCompleteGitHubInstall()
  const [state, setState] = useState<State>({ kind: 'working' })
  const sent = useRef(false)

  useEffect(() => {
    if (sent.current) return
    sent.current = true
    const action = params.get('setup_action') ?? ''
    const id = Number(params.get('installation_id') ?? '')
    const code = params.get('code') ?? ''
    const st = params.get('state') ?? ''
    // The code and state are single-use and read once: take them out of the
    // address bar and the history entry as soon as they are in hand.
    const clearQuery = () => router.replace(pathname)
    if (action === 'request') {
      setState({ kind: 'requested' })
      clearQuery()
      return
    }
    if (!Number.isSafeInteger(id) || id <= 0 || !st) {
      setState({
        kind: 'error',
        message: t('scans.ci.callback.missing', 'GitHub did not send the installation details.'),
      })
      clearQuery()
      return
    }
    trigger({ installation_id: id, code, state: st })
      .then((inst) => setState({ kind: 'done', account: inst?.account_login ?? '' }))
      .catch((e: unknown) => setState({ kind: 'error', message: getErrorMessage(e) }))
      .finally(clearQuery)
  }, [params, trigger, t, router, pathname])

  return (
    <Card className="mx-auto mt-8 max-w-xl" data-testid="ci-github-callback">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          {state.kind === 'done' ? (
            <CheckCircle2 className="size-5 text-success" aria-hidden />
          ) : state.kind === 'error' ? (
            <ShieldX className="size-5 text-destructive" aria-hidden />
          ) : null}
          {t('scans.ci.callback.title', 'GitHub App installation')}
        </CardTitle>
        <CardDescription>
          {state.kind === 'working' &&
            t('scans.ci.callback.working', 'Checking the installation with GitHub…')}
          {state.kind === 'done' &&
            t(
              'scans.ci.callback.done',
              'Installed on {account}. CI runs of its repositories now post the OpenCTEM gate check and a pull request comment.',
              {
                account: state.account,
                product: brand.name,
              }
            )}
          {state.kind === 'requested' &&
            t(
              'scans.ci.callback.requested',
              'GitHub sent the install request to an owner of the organization. Come back here after they approve it.'
            )}
          {state.kind === 'error' && state.message}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Button asChild size="sm" variant="outline">
          <Link href="/ci-cd?tab=setup&section=feedback">
            {t('scans.ci.callback.back', 'Back to CI trust and gate')}
          </Link>
        </Button>
      </CardContent>
    </Card>
  )
}
