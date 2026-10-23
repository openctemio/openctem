'use client'

import { useEffect, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  StackedCell,
  EmptyState,
  DataTable,
  DataTableColumnHeader,
  ErrorState,
  GatedButton,
  MetricStrip,
  type MetricStripItem,
} from '@/features/shared'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { KeyRound, Plus, Ban, Copy, Check, ShieldCheck, RefreshCw } from 'lucide-react'
import {
  useScimTokens,
  useCreateScimToken,
  useRevokeScimToken,
  useRotateScimToken,
} from '@/features/scim-tokens/api/use-scim-tokens'
import {
  SCIM_TOKEN_DEFAULT_LIFETIME_DAYS,
  SCIM_TOKEN_LIFETIME_DAYS,
  type ScimToken,
} from '@/features/scim-tokens/types/scim-token.types'
import { copyToClipboard } from '@/lib/clipboard'
import { getErrorMessage } from '@/lib/api/error-handler'
import { toast } from 'sonner'
import { usePermissions } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

function scimOwnerOnlyReason(tr: ReturnType<typeof useTranslation>['t']): string {
  return tr(
    'settings.scim.ownerOnly',
    'Only the organization owner can generate or revoke SCIM tokens: a token can create, suspend and re-role every member.'
  )
}

function isActive(t: ScimToken): boolean {
  return t.status === 'active'
}

function StatusBadge({ t }: { t: ScimToken }) {
  const { t: tr } = useTranslation()
  if (t.status === 'expired') {
    return <Badge variant="outline">{tr('settings.scim.status.expired', 'Expired')}</Badge>
  }
  if (!isActive(t)) {
    return <Badge variant="secondary">{tr('settings.scim.status.revoked', 'Revoked')}</Badge>
  }
  return <Badge variant="default">{tr('settings.scim.status.active', 'Active')}</Badge>
}

// ─────────────────────────────────────────────────────────
// Generate dialog + one-time reveal
// ─────────────────────────────────────────────────────────

function GenerateTokenDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  onCreated: (plaintext: string) => void
}) {
  const [name, setName] = useState('')
  const [days, setDays] = useState<number>(SCIM_TOKEN_DEFAULT_LIFETIME_DAYS)
  const { trigger, isMutating } = useCreateScimToken()
  const { t: tr } = useTranslation()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return toast.error(tr('settings.keys.nameRequired', 'Name is required'))
    try {
      const res = await trigger({ name: name.trim(), expires_in_days: days })
      onCreated(res?.token ?? '')
      onOpenChange(false)
      setName('')
      setDays(SCIM_TOKEN_DEFAULT_LIFETIME_DAYS)
    } catch (error) {
      toast.error(
        getErrorMessage(error, tr('settings.scim.createFailed', 'Failed to create SCIM token'))
      )
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{tr('settings.scim.dialog.title', 'Generate SCIM token')}</DialogTitle>
          <DialogDescription>
            {tr(
              'settings.scim.dialog.description',
              'Your identity provider presents this token as a bearer credential when provisioning users. The secret is shown once.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="scim-token-name">{tr('settings.keys.name', 'Name')}</Label>
              <Input
                id="scim-token-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={tr('settings.scim.dialog.namePlaceholder', 'Okta production')}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="scim-token-expiry">
                {tr('settings.scim.expiry.label', 'Expires after')}
              </Label>
              <Select value={String(days)} onValueChange={(v) => setDays(Number(v))}>
                <SelectTrigger id="scim-token-expiry">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SCIM_TOKEN_LIFETIME_DAYS.map((d) => (
                    <SelectItem key={d} value={String(d)}>
                      {tr('settings.scim.expiry.days', '{days} days', { days: d })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-muted-foreground text-xs">
                {tr(
                  'settings.scim.expiry.hint',
                  'The token stops working after this time. Rotate it before then; the old token keeps working for 24 hours after a rotation.'
                )}
              </p>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {tr('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={isMutating}>
              {isMutating
                ? tr('settings.keys.generating', 'Generating…')
                : tr('settings.keys.generate', 'Generate')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

function RevealTokenDialog({ value, onClose }: { value: string; onClose: () => void }) {
  const { t: tr } = useTranslation()
  const [copied, setCopied] = useState(false)
  async function copy() {
    const ok = await copyToClipboard(value)
    if (ok) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } else {
      toast.error(tr('settings.keys.copyFailed', 'Copy failed'))
    }
  }
  return (
    <Dialog open={!!value} onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{tr('settings.scim.reveal.title', 'Copy your SCIM token')}</DialogTitle>
          <DialogDescription>
            {tr(
              'settings.scim.reveal.description',
              "This is the only time the full token is shown. Paste it into your IdP's SCIM configuration as the bearer token, then store it securely."
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="bg-muted flex items-center gap-2 rounded-md p-3">
            <code className="flex-1 break-all text-xs">{value}</code>
            <Button
              size="icon"
              variant="ghost"
              onClick={copy}
              title={tr('settings.keys.copy', 'Copy')}
              aria-label={tr('settings.scim.reveal.copyLabel', 'Copy token')}
            >
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            </Button>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button onClick={onClose}>{tr('settings.keys.done', 'Done')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ─────────────────────────────────────────────────────────
// IdP setup card (base URL)
// ─────────────────────────────────────────────────────────

function ScimEndpointCard() {
  const { t: tr } = useTranslation()
  const [baseURL, setBaseURL] = useState('')
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setBaseURL(`${window.location.origin}/scim/v2`)
    }
  }, [])
  async function copy() {
    const ok = await copyToClipboard(baseURL)
    if (ok) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } else {
      toast.error(tr('settings.keys.copyFailed', 'Copy failed'))
    }
  }
  return (
    <Card className="mt-5">
      <CardHeader>
        <CardTitle>{tr('settings.scim.endpoint.title', 'SCIM endpoint')}</CardTitle>
        <CardDescription>
          {tr(
            'settings.scim.endpoint.description',
            'Configure your identity provider (Okta, Microsoft Entra ID, etc.) with this base URL and a token below. Authentication uses an HTTP bearer token.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="bg-muted flex items-center gap-2 rounded-md p-3">
          <code className="flex-1 break-all text-xs">{baseURL || '…'}</code>
          <Button
            size="icon"
            variant="ghost"
            onClick={copy}
            title={tr('settings.keys.copy', 'Copy')}
            aria-label={tr('settings.scim.endpoint.copyLabel', 'Copy base URL')}
            disabled={!baseURL}
          >
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

// ─────────────────────────────────────────────────────────
// Token actions cell (inline revoke button + confirm dialog)
// ─────────────────────────────────────────────────────────

function TokenActionsCell({
  t,
  onChanged,
  onRotated,
  canRevoke,
}: {
  t: ScimToken
  onChanged: () => void
  onRotated: (plaintext: string) => void
  canRevoke: boolean
}) {
  const [revokeOpen, setRevokeOpen] = useState(false)
  const [rotateOpen, setRotateOpen] = useState(false)
  // `t` is the token here, so the translator is `tr`.
  const { t: tr } = useTranslation()
  const ownerOnlyReason = scimOwnerOnlyReason(tr)
  const { trigger: revoke, isMutating: revoking } = useRevokeScimToken()
  const { trigger: rotate, isMutating: rotating } = useRotateScimToken()

  async function handleRotate() {
    try {
      const res = await rotate(t.id)
      toast.success(
        tr('settings.scim.rotate.done', 'Token rotated. The old token stops working in 24 hours.')
      )
      setRotateOpen(false)
      onRotated(res?.token ?? '')
      onChanged()
    } catch (error) {
      toast.error(
        getErrorMessage(error, tr('settings.scim.rotate.failed', 'Failed to rotate the token'))
      )
    }
  }

  async function handleRevoke() {
    try {
      await revoke(t.id)
      toast.success(tr('settings.scim.revoked', 'Token revoked'))
      setRevokeOpen(false)
      onChanged()
    } catch (error) {
      toast.error(getErrorMessage(error, tr('settings.scim.revokeFailed', 'Failed to revoke')))
    }
  }

  return (
    <div className="text-right">
      {isActive(t) && (
        <GatedButton
          variant="ghost"
          size="icon"
          allowed={canRevoke}
          reason={ownerOnlyReason}
          onClick={() => setRotateOpen(true)}
          title={canRevoke ? tr('settings.scim.rotate.confirm', 'Rotate') : undefined}
          aria-label={tr('settings.scim.rotate.label', 'Rotate {name}', { name: t.name })}
        >
          <RefreshCw className="h-4 w-4" />
        </GatedButton>
      )}
      {isActive(t) && (
        <GatedButton
          variant="ghost"
          size="icon"
          allowed={canRevoke}
          reason={ownerOnlyReason}
          onClick={() => setRevokeOpen(true)}
          title={canRevoke ? tr('confirm.revoke', 'Revoke') : undefined}
          aria-label={tr('confirm.scimToken.revokeLabel', 'Revoke {name}', { name: t.name })}
          className="text-destructive hover:text-destructive"
        >
          <Ban className="h-4 w-4" />
        </GatedButton>
      )}
      <ConfirmDialog
        open={revokeOpen}
        onOpenChange={setRevokeOpen}
        title={tr('confirm.scimToken.revokeTitle', 'Revoke the SCIM token {name}?', {
          name: t.name,
        })}
        desc={tr(
          'confirm.scimToken.revokeDesc',
          'Your identity provider loses access to SCIM provisioning with this token at once. This cannot be undone.'
        )}
        confirmText={
          revoking ? tr('confirm.revoking', 'Revoking…') : tr('confirm.revoke', 'Revoke')
        }
        destructive
        isLoading={revoking}
        typeToConfirm={t.name}
        handleConfirm={() => void handleRevoke()}
      />
      <ConfirmDialog
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        title={tr('settings.scim.rotate.title', 'Rotate the SCIM token {name}?', { name: t.name })}
        desc={tr(
          'settings.scim.rotate.desc',
          'A new token is generated and shown once. The current token keeps working for 24 hours so you can update your identity provider, then it stops.'
        )}
        confirmText={
          rotating
            ? tr('settings.scim.rotate.rotating', 'Rotating…')
            : tr('settings.scim.rotate.confirm', 'Rotate')
        }
        isLoading={rotating}
        handleConfirm={() => void handleRotate()}
      />
    </div>
  )
}

/** "Generate token" — enabled for the owner, disabled with the reason for administrators. */
function GenerateTokenButton({ canMint, onClick }: { canMint: boolean; onClick: () => void }) {
  const { t: tr } = useTranslation()
  return (
    <GatedButton size="sm" allowed={canMint} reason={scimOwnerOnlyReason(tr)} onClick={onClick}>
      <Plus className="me-2 h-4 w-4" />
      {tr('settings.scim.generate', 'Generate token')}
    </GatedButton>
  )
}

// ─────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <div className="mt-5 space-y-5">
      <Skeleton className="h-16 w-full rounded-xl" />
      <Skeleton className="h-28 w-full rounded-xl" />
      <Skeleton className="h-64 w-full rounded-lg" />
    </div>
  )
}

export default function ScimTokensPage() {
  // SCIM tokens are an owner/admin operation: the API refuses every
  // /scim-tokens call from anyone else. Members and viewers used to get an
  // enabled "Generate token" button (and an error where the list should be).
  const { isAdmin, isOwner, isLoading: roleLoading } = usePermissions()
  const canManage = isAdmin()
  // Minting and revoking a token is the owner's (the API refuses admins).
  const canMint = isOwner()
  const { data, error, isLoading, mutate } = useScimTokens({ enabled: canManage })
  const { t: tr } = useTranslation()
  const [genOpen, setGenOpen] = useState(false)
  const [newToken, setNewToken] = useState('')

  const tokens = useMemo(() => data?.tokens ?? [], [data])
  const stats = useMemo(() => {
    const active = tokens.filter(isActive).length
    const expired = tokens.filter((t) => t.status === 'expired').length
    return { total: tokens.length, active, expired, revoked: tokens.length - active - expired }
  }, [tokens])

  const columns = useMemo<ColumnDef<ScimToken>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={tr('settings.keys.name', 'Name')} />
        ),
        cell: ({ row }) => {
          const t = row.original
          return <StackedCell primary={t.name} secondary={<code>{t.prefix}…</code>} />
        },
      },
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={tr('settings.keys.status', 'Status')} />
        ),
        cell: ({ row }) => <StatusBadge t={row.original} />,
      },
      {
        accessorKey: 'created_at',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={tr('settings.keys.created', 'Created')} />
        ),
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs">
            {new Date(row.original.created_at).toLocaleDateString()}
          </span>
        ),
      },
      {
        accessorKey: 'last_used_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={tr('settings.keys.lastUsed', 'Last used')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs">
            {row.original.last_used_at
              ? new Date(row.original.last_used_at).toLocaleDateString()
              : tr('settings.keys.never', 'Never')}
          </span>
        ),
      },
      {
        accessorKey: 'expires_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={tr('settings.scim.column.expires', 'Expires')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs">
            {row.original.expires_at ? new Date(row.original.expires_at).toLocaleDateString() : ''}
          </span>
        ),
      },
      {
        id: 'actions',
        header: '',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => (
          <TokenActionsCell
            t={row.original}
            onChanged={() => mutate()}
            onRotated={setNewToken}
            canRevoke={canMint}
          />
        ),
      },
    ],
    [mutate, canMint, tr]
  )

  const metrics: MetricStripItem[] = [
    { key: 'total', label: tr('settings.scim.metric.total', 'Total tokens'), value: stats.total },
    {
      key: 'active',
      label: tr('settings.scim.metric.active', 'Active tokens'),
      value: stats.active,
    },
    {
      key: 'expired',
      label: tr('settings.scim.metric.expired', 'Expired tokens'),
      value: stats.expired,
    },
    {
      key: 'revoked',
      label: tr('settings.scim.metric.revoked', 'Revoked tokens'),
      value: stats.revoked,
    },
  ]

  return (
    <Main>
      <PageHeader
        title={tr('settings.scim.title', 'Directory sync (SCIM)')}
        description={tr(
          'settings.scim.description',
          'Automate user provisioning and deprovisioning from your identity provider.'
        )}
      >
        {canManage && <GenerateTokenButton canMint={canMint} onClick={() => setGenOpen(true)} />}
      </PageHeader>

      {roleLoading ? (
        <LoadingSkeleton />
      ) : !canManage ? (
        <div className="mt-5">
          <EmptyState
            icon={ShieldCheck}
            title={tr('settings.scim.managed.title', "Managed by your team's owners and admins")}
            description={tr(
              'settings.scim.managed.description',
              'SCIM tokens let your identity provider create and remove accounts in this team. Ask an owner or admin to set it up.'
            )}
          />
        </div>
      ) : isLoading ? (
        <LoadingSkeleton />
      ) : error ? (
        // Don't render a failed read as "No SCIM tokens yet" with zeroed stats.
        <div className="mt-5">
          <ErrorState
            title={tr('settings.scim.errorTitle', 'SCIM tokens')}
            error={error}
            onRetry={() => void mutate()}
          />
        </div>
      ) : (
        <>
          <MetricStrip className="mt-5" items={metrics} />

          <ScimEndpointCard />

          <div className="mt-5">
            {tokens.length === 0 ? (
              <EmptyState
                icon={KeyRound}
                title={tr('settings.scim.emptyTitle', 'No SCIM tokens yet')}
                description={tr(
                  'settings.scim.emptyDescription',
                  'Generate a token to connect your identity provider for automated user provisioning.'
                )}
                action={<GenerateTokenButton canMint={canMint} onClick={() => setGenOpen(true)} />}
              />
            ) : (
              <DataTable
                columns={columns}
                data={tokens}
                getRowId={(t) => t.id}
                searchPlaceholder={tr('settings.scim.searchPlaceholder', 'Search tokens…')}
                showSelectionCount={false}
              />
            )}
          </div>
        </>
      )}

      <GenerateTokenDialog
        open={genOpen}
        onOpenChange={setGenOpen}
        onCreated={(plaintext) => {
          setNewToken(plaintext)
          mutate()
        }}
      />
      <RevealTokenDialog value={newToken} onClose={() => setNewToken('')} />
    </Main>
  )
}
