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
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { EntryBanner } from '@/components/entry'
import { useBrand } from '@/context/brand-provider'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
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

  const tone = state.kind === 'done' ? 'ok' : state.kind === 'error' ? 'danger' : 'info'

  return (
    <PageStack data-testid="ci-github-callback">
      <PageHeader title={t('scans.ci.callback.title', 'GitHub App installation')} />
      <div className="flex max-w-xl flex-col gap-4">
        <EntryBanner tone={tone}>
          <p className="flex items-center gap-2">
            {state.kind === 'working' && (
              <Loader2
                aria-hidden
                className="size-4 shrink-0 animate-spin motion-reduce:animate-none"
              />
            )}
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
          </p>
        </EntryBanner>
        <div>
          <Button asChild variant="outline">
            <Link href="/ci-cd?tab=setup&section=feedback">
              {t('scans.ci.callback.back', 'Back to CI/CD settings')}
            </Link>
          </Button>
        </div>
      </div>
    </PageStack>
  )
}
