'use client'

import { useId, useState } from 'react'
import { Loader2, Pencil, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import {
  LimitsUsageTable,
  useLimitKeyLabel,
  type LimitUsageRow,
} from '@/features/limits/components/limits-usage-table'
import {
  formatLimit,
  isLimitKey,
  ORGANIZATION_LIMIT_KEYS,
  parseLimit,
  type LimitKey,
} from '@/features/limits/lib/limit-keys'
import { ErrorState } from '@/features/shared'
import type { AdminLimitsResponse, EffectiveLimit } from '@/lib/api/generated'
import { deleteTenantLimit, putTenantLimit, useTenantLimits } from '../api/use-limits'

const MAX_REASON = 500

type Row = LimitUsageRow & {
  origin?: string
  reason?: string
  expires_at?: string
}

/** One row per organization key, from the server's effective limits. */
export function limitRows(limits: EffectiveLimit[] | undefined): Row[] {
  return ORGANIZATION_LIMIT_KEYS.map((key) => {
    const l = limits?.find((x) => x.key === key)
    return {
      key,
      limit: l?.limit,
      used: l?.used,
      over_limit: l?.over_limit,
      uncounted: l?.uncounted,
      origin: l?.origin,
      reason: l?.reason,
      expires_at: l?.expires_at,
    }
  })
}

export interface OrganizationLimitsPanelProps {
  tenantId: string
  /** Operations admins and up set and remove limits. */
  canManage: boolean
}

/**
 * Console > Organizations > an organization > Limits: usage per limit with
 * an over-limit badge, and who set each limit. An administrator sets or
 * removes limits of this installation's operator (a reason is required, an
 * expiry is optional); limits set by the service operator are read-only here.
 * A lower limit never removes anything: new additions over it are refused.
 */
export function OrganizationLimitsPanel({ tenantId, canManage }: OrganizationLimitsPanelProps) {
  const { t, locale } = useTranslation()
  const keyLabel = useLimitKeyLabel()
  const { data, error, isLoading, mutate } = useTenantLimits(tenantId)
  const [editing, setEditing] = useState<LimitKey | null>(null)
  const [pendingRemove, setPendingRemove] = useState<LimitKey | null>(null)

  if (error) {
    return (
      <ErrorState
        title={t('limits.loadError', 'the limits')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) {
    return <Skeleton className="h-80 w-full" />
  }

  const rows = limitRows(data.limits)
  const editingRow = editing ? rows.find((r) => r.key === editing) : undefined

  const remove = async (key: LimitKey) => {
    try {
      await mutate(await deleteTenantLimit(tenantId, key), { revalidate: false })
      setPendingRemove(null)
      toast.success(
        t('limits.console.org.removed', '{limit}: limit removed', { limit: keyLabel(key) })
      )
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('limits.console.org.removeError', 'Could not remove the limit')
      )
    }
  }

  const note = (row: Row) => {
    if (!row.origin) return null
    const who =
      row.origin === 'control_plane'
        ? t('limits.console.origin.setByService', 'Set by the service operator')
        : t('limits.console.origin.setByOperator', 'Set by an administrator')
    return (
      <span className="text-xs text-muted-foreground" data-origin={row.origin}>
        {who}
        {row.expires_at
          ? ` ${t('limits.until', 'until {date}', {
              date: new Date(row.expires_at).toLocaleDateString(locale),
            })}`
          : ''}
        {row.reason ? `: ${row.reason}` : ''}
      </span>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          {t('limits.console.org.title', 'Limits')}
          {data.over_limit && (
            <Badge variant="destructive">{t('limits.overLimit', 'Over limit')}</Badge>
          )}
        </CardTitle>
        <CardDescription>
          {t(
            'limits.console.org.description',
            'No limit applies unless one is set. A lower limit never removes anything: new additions over it are refused.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <LimitsUsageTable
          rows={rows}
          limitNote={note}
          actionColumn={canManage ? t('limits.console.org.actions', 'Change') : undefined}
          action={
            canManage
              ? (row) =>
                  row.origin === 'control_plane' ? null : (
                    <div className="flex justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setEditing(row.key)}
                        aria-label={t('limits.console.org.editAria', 'Set the {limit} limit', {
                          limit: keyLabel(row.key),
                        })}
                      >
                        <Pencil className="size-4" />
                      </Button>
                      {row.origin === 'operator' && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setPendingRemove(row.key)}
                          aria-label={t(
                            'limits.console.org.removeAria',
                            'Remove the {limit} limit',
                            { limit: keyLabel(row.key) }
                          )}
                        >
                          <RotateCcw className="size-4" />
                        </Button>
                      )}
                    </div>
                  )
              : undefined
          }
        />
        {!canManage && (
          <p className="mt-3 text-sm text-muted-foreground">
            {t('limits.console.org.needsOps', 'Changing a limit needs an operations admin.')}
          </p>
        )}
      </CardContent>
      {editing && (
        <LimitDialog
          key={editing}
          tenantId={tenantId}
          limitKey={editing}
          current={editingRow?.limit}
          currentReason={editingRow?.origin === 'operator' ? editingRow.reason : undefined}
          onClose={() => setEditing(null)}
          onSaved={(next) => {
            void mutate(next, { revalidate: false })
            setEditing(null)
          }}
        />
      )}
      <ConfirmDialog
        open={pendingRemove !== null}
        onOpenChange={(o) => !o && setPendingRemove(null)}
        destructive
        title={t('limits.console.org.removeTitle', 'Remove the {limit} limit?', {
          limit: pendingRemove ? keyLabel(pendingRemove) : '',
        })}
        desc={t(
          'limits.console.org.removeDesc',
          'The organization is no longer limited by it, unless the service operator set one.'
        )}
        confirmText={t('limits.console.org.remove', 'Remove the limit')}
        handleConfirm={() => (pendingRemove ? remove(pendingRemove) : undefined)}
      />
    </Card>
  )
}

function LimitDialog({
  tenantId,
  limitKey,
  current,
  currentReason,
  onClose,
  onSaved,
}: {
  tenantId: string
  limitKey: LimitKey
  current?: number
  currentReason?: string
  onClose: () => void
  onSaved: (next: AdminLimitsResponse) => void
}) {
  const { t } = useTranslation()
  const keyLabel = useLimitKeyLabel()
  const id = useId()
  const [value, setValue] = useState(current === undefined || current < 0 ? '' : String(current))
  const [reason, setReason] = useState(currentReason ?? '')
  const [expires, setExpires] = useState('')
  const [busy, setBusy] = useState(false)
  // Local yyyy-mm-dd, read once when the dialog opens.
  const [today] = useState(() => {
    const d = new Date()
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
  })

  const parsed = parseLimit(value)
  const expiryBad = !!expires && expires < today
  const reasonBad = reason.trim() === '' || reason.trim().length > MAX_REASON
  const invalid = parsed === null || reasonBad || expiryBad || !isLimitKey(limitKey)

  const save = async () => {
    if (parsed === null) return
    setBusy(true)
    try {
      onSaved(
        await putTenantLimit(tenantId, limitKey, {
          value: parsed,
          reason: reason.trim(),
          // An expiry runs to the end of the chosen day.
          expires_at: expires ? new Date(`${expires}T23:59:59`).toISOString() : undefined,
        })
      )
      toast.success(
        t('limits.console.org.saved', '{limit} limit set', { limit: keyLabel(limitKey) })
      )
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('limits.console.org.saveError', 'Could not set the limit')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {t('limits.console.org.dialogTitle', '{limit} for this organization', {
              limit: keyLabel(limitKey),
            })}
          </DialogTitle>
          <DialogDescription>
            {t('limits.console.org.dialogDesc', 'Now {current}. Recorded in the admin audit log.', {
              current: formatLimit(current, t('limits.unlimited', 'Unlimited')),
            })}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor={`${id}-v`}>{t('limits.col.item', 'Limit')}</Label>
              <Input
                id={`${id}-v`}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={t('limits.unlimited', 'Unlimited')}
                inputMode="numeric"
                aria-invalid={parsed === null}
              />
              <p className="text-xs text-muted-foreground">
                {t('limits.console.org.emptyHint', 'Leave empty for no limit.')}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-r`}>{t('limits.console.reason', 'Reason')}</Label>
              <Textarea
                id={`${id}-r`}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={MAX_REASON}
                rows={2}
                aria-invalid={reasonBad && reason !== ''}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-e`}>{t('limits.console.expires', 'Expires (optional)')}</Label>
              <Input
                id={`${id}-e`}
                type="date"
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
                aria-invalid={expiryBad}
              />
              {expiryBad && (
                <p className="text-sm text-destructive">
                  {t('limits.console.expiryPast', 'Pick a date in the future.')}
                </p>
              )}
            </div>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('limits.console.cancel', 'Cancel')}
          </Button>
          <Button onClick={() => void save()} disabled={invalid || busy}>
            {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
            {t('limits.console.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
