'use client'

import { useCallback, useEffect, useState } from 'react'
import { CheckCircle2, Loader2, XCircle } from 'lucide-react'

import { EntryActions, EntryBanner, EntryCard, EntryHeader } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'

import { decideConfirmation, fetchConfirmation, type McpConfirmation } from '../api/confirmations'
import { isRequestId } from '../api/consent'

/**
 * Confirms a change an AI application asked to make (RFC-062 §10). The
 * page is OpenCTEM's, outside the application: the AI application cannot answer it.
 * It shows the exact action as the server describes it; approving lets the
 * application run it once within five minutes.
 */
export function ConfirmView({ id }: { id: string | null }) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const [item, setItem] = useState<McpConfirmation | null | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<'approved' | 'denied' | null>(null)
  const [error, setError] = useState<'load' | 'notOpen' | null>(null)
  const valid = isRequestId(id)
  const errorText =
    error === 'load'
      ? t('mcp.confirm.loadFailed', 'Could not load the request.')
      : error === 'notOpen'
        ? t('mcp.confirm.notOpen', 'This request is no longer open (expired or already answered).')
        : null
  const tenantId = currentTenant?.id
  const orgName = currentTenant?.name ?? t('mcp.confirm.thisOrganization', 'this organization')

  const load = useCallback(async () => {
    if (!valid || !tenantId) return
    try {
      setItem(await fetchConfirmation(id))
    } catch {
      setError('load')
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
    else setError('notOpen')
  }

  if (!valid)
    return (
      <Message
        title={t('mcp.confirm.nothing', 'Nothing to confirm')}
        text={t('mcp.confirm.invalidLink', 'This link is not a valid confirmation.')}
      />
    )
  if (item === undefined && !error) {
    return (
      <EntryCard aria-busy="true">
        <Skeleton className="h-8 w-2/3" />
        <Skeleton className="h-20 w-full" />
      </EntryCard>
    )
  }
  if (!item) {
    return (
      <Message
        title={t('mcp.confirm.nothing', 'Nothing to confirm')}
        text={
          errorText ??
          t(
            'mcp.confirm.notFound',
            'No such request for you in {org}. Make sure you are signed in as the person who connected the application, in the same organization.',
            { org: orgName }
          )
        }
      />
    )
  }
  if (done) {
    return (
      <Message
        title={
          done === 'approved'
            ? t('mcp.confirm.confirmed', 'Confirmed')
            : t('mcp.confirm.refused', 'Refused')
        }
        text={
          done === 'approved'
            ? t(
                'mcp.confirm.confirmedDesc',
                'Go back to {client}: it can now make this change once, within five minutes.',
                { client: item.client_name }
              )
            : t('mcp.confirm.refusedDesc', '{client} will not make this change.', {
                client: item.client_name,
              })
        }
        icon={done === 'approved' ? 'ok' : 'no'}
      />
    )
  }
  const open = item.status === 'pending' && !item.expired

  return (
    <EntryCard>
      <EntryHeader
        className="break-words"
        title={t('mcp.confirm.title', '{client} wants to make a change', {
          client: item.client_name,
        })}
        description={t(
          'mcp.confirm.description',
          'Check exactly what it will do. It acts as you, in {org}.',
          {
            org: orgName,
          }
        )}
      />
      <pre className="bg-surface-sunken text-dense max-h-96 overflow-auto rounded-md p-3 break-words whitespace-pre-wrap">
        {item.summary}
      </pre>
      <EntryBanner tone="warn" role="alert">
        {t(
          'mcp.confirm.warning',
          'Only confirm if you asked the application to do this. An application can be tricked by content it reads.'
        )}
      </EntryBanner>
      {!open && (
        <EntryBanner tone="danger" role="alert">
          {item.expired
            ? t('mcp.confirm.expired', 'This request expired.')
            : t('mcp.confirm.alreadyDecided', 'This request was already answered.')}
        </EntryBanner>
      )}
      {error && (
        <EntryBanner tone="danger" role="alert">
          {errorText}
        </EntryBanner>
      )}
      <EntryActions layout="row">
        <Button variant="outline" disabled={busy || !open} onClick={() => void decide(false)}>
          {t('mcp.confirm.refuse', 'Refuse')}
        </Button>
        <Button variant="signal" disabled={busy || !open} onClick={() => void decide(true)}>
          {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
          {t('mcp.confirm.confirm', 'Confirm')}
        </Button>
      </EntryActions>
    </EntryCard>
  )
}

function Message({ title, text, icon }: { title: string; text: string; icon?: 'ok' | 'no' }) {
  return (
    <EntryCard>
      <EntryHeader
        title={
          <span className="flex items-center gap-2">
            {icon === 'ok' && <CheckCircle2 className="text-success size-5 shrink-0" aria-hidden />}
            {icon === 'no' && (
              <XCircle className="text-muted-foreground size-5 shrink-0" aria-hidden />
            )}
            {title}
          </span>
        }
        description={text}
      />
    </EntryCard>
  )
}
