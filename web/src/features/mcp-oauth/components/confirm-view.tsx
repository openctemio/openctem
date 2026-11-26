'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from '@/components/link'
import { CheckCircle2, Loader2, XCircle } from 'lucide-react'

import { EntryActions, EntryBanner, EntryCard, EntryHeader } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { hasServerText, messageOf, serverText } from '@/lib/server-text'

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
      <ConfirmSummary item={item} />
      <EntryBanner tone="warn">
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
  const { t } = useTranslation()
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
      {/* Every end state has a way on: nothing is left to do on this page. */}
      <EntryActions>
        <Button asChild variant="outline">
          <Link href="/">{t('common.access.toDashboard', 'Go to the dashboard')}</Link>
        </Button>
      </EntryActions>
    </EntryCard>
  )
}

const PRE =
  'bg-surface-sunken text-dense max-h-96 overflow-auto rounded-md p-3 break-words whitespace-pre-wrap'

/**
 * What the application asks to do. A summary with a known code is worded in
 * the reader's language, with the application's own text and the client
 * visibility as separate fields: text the application wrote can never pass
 * for the visibility line. Otherwise the server's English summary is shown.
 */
function ConfirmSummary({ item }: { item: McpConfirmation }) {
  const { t, locale } = useTranslation()
  const p = item.summary_params ?? {}
  const known =
    item.summary_code === 'mcp.add_finding_comment' &&
    typeof p.content === 'string' &&
    typeof p.finding === 'string' &&
    typeof p.severity === 'string' &&
    (p.client_visible === undefined || typeof p.client_visible === 'boolean')
  const msg = known
    ? messageOf(item.summary_code, { finding: p.finding, severity: p.severity })
    : undefined
  const lead = msg && hasServerText(t, locale, msg) ? serverText(t, locale, msg, '') : ''
  if (!known || !lead) {
    return <pre className={PRE}>{item.summary}</pre>
  }
  return (
    <div className="space-y-2" data-slot="mcp-confirm-summary">
      <p className="text-sm break-words">{lead}</p>
      <pre className={PRE} translate="no" aria-label={t('serverText.mcp.comment_label', 'Comment')}>
        {p.content as string}
      </pre>
      {typeof p.client_visible === 'boolean' && (
        <p className="text-sm font-medium" data-slot="mcp-confirm-visibility">
          {p.client_visible
            ? t('serverText.mcp.client_visible.yes', "Visible to the campaign's client: yes")
            : t(
                'serverText.mcp.client_visible.no',
                "Visible to the campaign's client: no (campaign team only)"
              )}
        </p>
      )}
    </div>
  )
}
