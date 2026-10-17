'use client'

import { useState } from 'react'
import { Check, Inbox, X } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatRelative } from '@/lib/format-date'

import {
  approveAccessRequest,
  denyAccessRequest,
  type McpAccessRequest,
  useAccessRequests,
} from '../api/access-requests'
import { useMcpLabels } from '../lib/use-mcp-labels'

interface AccessRequestsCardProps {
  canEdit: boolean
}

/**
 * Members' requests to approve an AI application's publisher. Approving adds
 * the publisher host to the approved publishers (a recent sign-in is asked
 * for); declining only closes the request. The requester is notified.
 */
export function AccessRequestsCard({ canEdit }: AccessRequestsCardProps) {
  const { t } = useTranslation()
  const { scopeShort } = useMcpLabels()
  const { data, isLoading } = useAccessRequests(true)
  const [pending, setPending] = useState<{ req: McpAccessRequest; approve: boolean } | null>(null)
  const [busy, setBusy] = useState(false)

  const decide = async () => {
    if (!pending) return
    setBusy(true)
    try {
      if (pending.approve) {
        await approveAccessRequest(pending.req.id)
        toast.success(
          t('mcp.requests.approved', '{host} approved. Members can connect its applications now.', {
            host: pending.req.client_host,
          })
        )
      } else {
        await denyAccessRequest(pending.req.id)
        toast.success(t('mcp.requests.declined', 'Request declined'))
      }
      setPending(null)
    } catch (err) {
      toast.error(getErrorMessage(err, t('mcp.requests.failed', 'Could not decide the request')))
    } finally {
      setBusy(false)
    }
  }

  const requests = data?.data ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {t('mcp.requests.title', 'Access requests')}
          {requests.length > 0 && <Badge variant="secondary">{requests.length}</Badge>}
        </CardTitle>
        <CardDescription>
          {t(
            'mcp.requests.description',
            'Members asked to connect these applications. Approving lets every member connect applications from that publisher; each person still approves what it may do.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : requests.length === 0 ? (
          <EmptyState
            icon={Inbox}
            title={t('mcp.requests.emptyTitle', 'No waiting requests')}
            description={t(
              'mcp.requests.emptyDescription',
              'When a member tries to connect an application you have not approved, they can ask you here.'
            )}
          />
        ) : (
          <ul className="divide-y rounded-md border">
            {requests.map((r) => (
              <li
                key={r.id}
                className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-medium break-words">{r.client_name}</span>
                    <span className="text-muted-foreground text-xs break-all">
                      {t('mcp.client.publishedBy', 'Published by {host}', { host: r.client_host })}
                    </span>
                  </div>
                  <p className="text-muted-foreground text-xs">
                    {t('mcp.requests.meta', 'Requested by {name} · {count} request(s) · {when}', {
                      name: r.requester_name || t('mcp.requests.formerMember', 'a former member'),
                      count: r.request_count,
                      when: formatRelative(r.updated_at),
                    })}
                  </p>
                  {r.scopes.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-muted-foreground text-xs">
                        {t('mcp.requests.asksFor', 'Asks for:')}
                      </span>
                      {r.scopes.map((s) => (
                        <Badge key={s} variant="outline" className="text-xs">
                          {scopeShort(s)}
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>
                {canEdit && (
                  <div className="flex shrink-0 gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPending({ req: r, approve: false })}
                    >
                      <X className="mr-2 h-4 w-4" aria-hidden />
                      {t('mcp.requests.deny', 'Decline')}
                    </Button>
                    <Button size="sm" onClick={() => setPending({ req: r, approve: true })}>
                      <Check className="mr-2 h-4 w-4" aria-hidden />
                      {t('mcp.requests.approve', 'Approve')}
                    </Button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(v) => !v && !busy && setPending(null)}
        destructive={pending ? !pending.approve : false}
        title={
          pending?.approve
            ? t('mcp.requests.approveTitle', 'Approve applications published by {host}?', {
                host: pending.req.client_host,
              })
            : t('mcp.requests.denyTitle', 'Decline the request for {host}?', {
                host: pending?.req.client_host ?? '',
              })
        }
        desc={
          pending?.approve
            ? t(
                'mcp.requests.approveDesc',
                'Every member can then connect applications whose identity is published on {host}. Each person still approves what it may do, and it never sees more than they can. You can remove the publisher at any time.',
                { host: pending.req.client_host }
              )
            : t(
                'mcp.requests.denyDesc',
                'The policy does not change. The member is told, and can ask again later.'
              )
        }
        confirmText={
          pending?.approve
            ? t('mcp.requests.approve', 'Approve')
            : t('mcp.requests.deny', 'Decline')
        }
        isLoading={busy}
        handleConfirm={() => decide()}
      />
    </Card>
  )
}
