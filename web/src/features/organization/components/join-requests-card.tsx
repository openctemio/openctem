'use client'

import { useState } from 'react'
import { Check, Loader2, X } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared'

import {
  approveJoinRequest,
  rejectJoinRequest,
  useJoinRequests,
  type JoinRole,
} from '../api/use-domain-signup'

/**
 * Members > Requests (api RFC-104): people with a verified address on one of
 * the organization's domains who asked to join. Owners and admins approve
 * (as viewer or member; nobody becomes an administrator by request) or
 * reject. Hidden when there is nothing waiting.
 */
export function JoinRequestsCard({
  canManage,
  onChanged,
}: {
  canManage: boolean
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const { requests, mutate } = useJoinRequests(canManage)
  const [roles, setRoles] = useState<Record<string, JoinRole>>({})
  const [busy, setBusy] = useState<string | null>(null)
  // Approving gives a person access, so it asks first.
  const [approving, setApproving] = useState<string | null>(null)

  if (!canManage || requests.length === 0) return null

  const decide = async (id: string, approve: boolean) => {
    setBusy(id)
    try {
      if (approve) {
        await approveJoinRequest(
          id,
          roles[id] ?? requests.find((r) => r.id === id)?.requested_role ?? 'viewer'
        )
        toast.success(t('org.joinRequests.approved'))
      } else {
        await rejectJoinRequest(id)
        toast.success(t('org.joinRequests.rejected'))
      }
      await mutate()
      onChanged?.()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('org.joinRequests.failed'))
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle className="text-base">
          {t('org.joinRequests.title', undefined, { count: String(requests.length) })}
        </CardTitle>
        <CardDescription>{t('org.joinRequests.desc')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {requests.map((r) => (
          <div
            key={r.id}
            className="flex flex-wrap items-center justify-between gap-3 border-b pb-3 last:border-0 last:pb-0"
          >
            <div className="min-w-0">
              <p className="truncate font-medium">{r.name || r.email}</p>
              <p className="flex flex-wrap items-center gap-x-3 text-xs text-muted-foreground">
                <span className="truncate">{r.email}</span>
                <RelativeTime date={r.requested_at} className="text-xs" />
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Select
                value={roles[r.id] ?? r.requested_role}
                onValueChange={(v) => setRoles((cur) => ({ ...cur, [r.id]: v as JoinRole }))}
              >
                <SelectTrigger className="h-8 w-28" aria-label={t('org.joinRequests.role')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="viewer">{t('settings.domains.role.viewer')}</SelectItem>
                  <SelectItem value="member">{t('settings.domains.role.member')}</SelectItem>
                </SelectContent>
              </Select>
              <Button size="sm" onClick={() => setApproving(r.id)} disabled={busy !== null}>
                {busy === r.id ? (
                  <Loader2 className="me-1.5 h-4 w-4 animate-spin" />
                ) : (
                  <Check className="me-1.5 h-4 w-4" />
                )}
                {t('org.joinRequests.approve')}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => void decide(r.id, false)}
                disabled={busy !== null}
              >
                <X className="me-1.5 h-4 w-4" />
                {t('org.joinRequests.reject')}
              </Button>
            </div>
          </div>
        ))}
        <p className="text-xs text-muted-foreground">{t('org.joinRequests.expiry')}</p>
      </CardContent>
      {(() => {
        const req = requests.find((r) => r.id === approving)
        const role = req ? (roles[req.id] ?? req.requested_role) : 'viewer'
        return (
          <ConfirmDialog
            open={!!req}
            onOpenChange={(open) => !open && setApproving(null)}
            title={t('confirm.joinRequest.title', 'Let {name} join?', {
              name: req ? req.name || req.email : '',
            })}
            desc={t(
              'confirm.joinRequest.desc',
              '{email} becomes a member of this organization now, as {role}, and can see what that role allows. You can change the role or remove them later.',
              { email: req?.email ?? '', role }
            )}
            confirmText={t('confirm.joinRequest.confirm', 'Approve request')}
            handleConfirm={async () => {
              if (req) await decide(req.id, true)
              setApproving(null)
            }}
          />
        )
      })()}
    </Card>
  )
}
