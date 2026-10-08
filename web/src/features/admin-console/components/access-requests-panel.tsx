'use client'

import { useState, type FormEvent } from 'react'
import { Check, Inbox, Loader2, X } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { EmptyState, ErrorState, RelativeTime } from '@/features/shared'
import { SetupLinkResult } from '@/features/shared/components/one-time-setup-link'
import type { AccessRequest, ApproveAccessRequestResult } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import {
  approveAccessRequest,
  rejectAccessRequest,
  useAccessRequests,
  type AccessRequestStatusFilter,
} from '../api/use-access-requests'

/** "Acme Corp" -> "acme-corp" (lowercase letters, digits, hyphens). */
export function slugFromCompany(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 50)
}

const STATUS_LABEL: Record<string, string> = {
  pending: 'Pending',
  unconfirmed: 'Email not confirmed',
  approved: 'Approved',
  rejected: 'Rejected',
}

function ApproveDialog({
  request,
  onClose,
  onDone,
}: {
  request: AccessRequest | null
  onClose: () => void
  onDone: () => void
}) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ApproveAccessRequestResult | null>(null)
  const [forId, setForId] = useState<string | null>(null)

  if (request && forId !== request.id) {
    setForId(request.id ?? null)
    setName(request.company ?? '')
    setSlug(slugFromCompany(request.company ?? ''))
    setError(null)
    setResult(null)
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!request?.id) return
    setBusy(true)
    setError(null)
    try {
      const res = await approveAccessRequest(request.id, { name: name.trim(), slug: slug.trim() })
      toast.success(`Organization created for ${request.email}`)
      if (res.owner_setup?.setup_token) {
        setResult(res)
      } else {
        onDone()
      }
    } catch (err) {
      setError(err instanceof AdminApiError ? err.message : 'Could not approve the request')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={!!request} onOpenChange={(o) => !o && !busy && (result ? onDone() : onClose())}>
      <DialogContent>
        {result?.owner_setup ? (
          <>
            <DialogHeader>
              <DialogTitle>Organization created</DialogTitle>
              <DialogDescription>
                Email could not be sent. Give the owner this one-time link.
              </DialogDescription>
            </DialogHeader>
            <SetupLinkResult
              outcome={{ ...result.owner_setup, email_sent: !!result.owner_setup.email_sent }}
              email={request?.email ?? ''}
            />
            <DialogFooter>
              <Button onClick={onDone}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <DialogHeader>
              <DialogTitle>Approve access request</DialogTitle>
              <DialogDescription>
                Creates the organization with {request?.email} as its owner. A new account gets a
                one-time set-password link by email.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-2">
              <Label htmlFor="ar-name">Organization name</Label>
              <Input
                id="ar-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={100}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ar-slug">Slug</Label>
              <Input
                id="ar-slug"
                value={slug}
                onChange={(e) => setSlug(e.target.value.toLowerCase())}
                pattern="[a-z0-9]+(-[a-z0-9]+)*"
                minLength={3}
                maxLength={50}
                required
              />
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
                Cancel
              </Button>
              <Button type="submit" disabled={busy || !name.trim() || slug.trim().length < 3}>
                {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
                Create organization
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

/**
 * Organizations > Access requests: people who asked for an organization while
 * sign-up is closed. Any administrator sees the queue; ops admins and super
 * admins approve or reject.
 */
export function AccessRequestsPanel({ canDecide }: { canDecide: boolean }) {
  const [status, setStatus] = useState<AccessRequestStatusFilter>('')
  const { data, error, isLoading, mutate } = useAccessRequests(status)
  const [approving, setApproving] = useState<AccessRequest | null>(null)
  const [rejecting, setRejecting] = useState<AccessRequest | null>(null)
  const [busy, setBusy] = useState(false)

  const reject = async () => {
    if (!rejecting?.id) return
    setBusy(true)
    try {
      await rejectAccessRequest(rejecting.id)
      toast.success('Request rejected')
      setRejecting(null)
      void mutate()
    } catch (err) {
      toast.error(err instanceof AdminApiError ? err.message : 'Could not reject the request')
    } finally {
      setBusy(false)
    }
  }

  const rows = data?.data ?? []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">
          {data ? `${data.total ?? 0} ${status ? STATUS_LABEL[status].toLowerCase() : 'open'}` : ''}
        </p>
        <Select
          value={status || 'open'}
          onValueChange={(v) => setStatus(v === 'open' ? '' : (v as AccessRequestStatusFilter))}
        >
          <SelectTrigger className="w-48" aria-label="Status">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="unconfirmed">Email not confirmed</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {error ? (
        <ErrorState title="access requests" error={error} onRetry={() => void mutate()} />
      ) : isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={Inbox}
          title="No requests"
          description="Requests appear here when sign-up is closed and request access is on (System > Sign-up)."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Received</TableHead>
                <TableHead>Company</TableHead>
                <TableHead>Requester</TableHead>
                <TableHead>Note</TableHead>
                <TableHead>Status</TableHead>
                {canDecide && <TableHead className="text-end">Decision</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.id}>
                  <TableCell>
                    <RelativeTime date={r.created_at} />
                  </TableCell>
                  <TableCell className="font-medium">{r.company}</TableCell>
                  <TableCell>{r.email}</TableCell>
                  <TableCell className="max-w-xs truncate text-sm text-muted-foreground">
                    {r.note}
                  </TableCell>
                  <TableCell>
                    <Badge variant={r.status === 'pending' ? 'default' : 'outline'}>
                      {STATUS_LABEL[r.status ?? ''] ?? r.status}
                    </Badge>
                  </TableCell>
                  {canDecide && (
                    <TableCell className="text-end">
                      {(r.status === 'pending' || r.status === 'unconfirmed') && (
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            disabled={r.status !== 'pending'}
                            title={
                              r.status !== 'pending'
                                ? 'The requester has not confirmed the email yet'
                                : undefined
                            }
                            onClick={() => setApproving(r)}
                          >
                            <Check className="me-1 size-4" />
                            Approve
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => setRejecting(r)}>
                            <X className="me-1 size-4" />
                            Reject
                          </Button>
                        </div>
                      )}
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <ApproveDialog
        request={approving}
        onClose={() => setApproving(null)}
        onDone={() => {
          setApproving(null)
          void mutate()
        }}
      />
      <ConfirmDialog
        open={!!rejecting}
        onOpenChange={(o) => !o && !busy && setRejecting(null)}
        title="Reject this request?"
        desc={
          rejecting?.confirmed
            ? `${rejecting?.email} gets a short email saying the request was not approved.`
            : 'The requester never confirmed the email, so no email is sent.'
        }
        destructive
        isLoading={busy}
        handleConfirm={() => void reject()}
        confirmText="Reject"
      />
    </div>
  )
}
