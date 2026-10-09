'use client'

import { useState } from 'react'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  createOrgClient,
  deleteOrgClient,
  type McpOrgClient,
  useOrgClients,
} from '../api/connections'

interface OrgClientsCardProps {
  canEdit: boolean
}

/** Redirect URIs, one per line. */
export function parseRedirectUris(text: string): string[] {
  return text
    .split(/\s+/)
    .map((u) => u.trim())
    .filter(Boolean)
}

/**
 * Applications the organization registers in advance (RFC-062 §5): members
 * see them as "registered by your organization", and no other organization
 * can use them. The client id is not a secret; the application proves itself
 * with PKCE and may only return to the exact redirect URIs listed here.
 */
export function OrgClientsCard({ canEdit }: OrgClientsCardProps) {
  const { data, isLoading } = useOrgClients(true)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [uris, setUris] = useState('')
  const [saving, setSaving] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<McpOrgClient | null>(null)

  const create = async () => {
    setSaving(true)
    try {
      const c = await createOrgClient(name.trim(), parseRedirectUris(uris))
      toast.success(`${c.name} registered. Give its client id to the application.`)
      setOpen(false)
      setName('')
      setUris('')
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not register the application'))
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!pendingDelete) return
    setSaving(true)
    try {
      await deleteOrgClient(pendingDelete.id)
      toast.success(`${pendingDelete.name} deleted; its connections ended`)
      setPendingDelete(null)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not delete the application'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
        <div className="space-y-1.5">
          <CardTitle>Applications registered by your organization</CardTitle>
          <CardDescription>
            For an AI application your organization runs or vouches for. Give it the client id; it
            can only return to the addresses listed here.
          </CardDescription>
        </div>
        {canEdit && (
          <Button size="sm" onClick={() => setOpen(true)}>
            <Plus className="mr-2 h-4 w-4" aria-hidden />
            Register
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : !data || data.data.length === 0 ? (
          <p className="text-muted-foreground text-sm">None registered.</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {data.data.map((c) => (
              <li
                key={c.id}
                className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0 space-y-1">
                  <p className="font-medium break-words">{c.name}</p>
                  <p className="font-mono text-xs break-all">{c.client_id}</p>
                  <p className="text-muted-foreground text-xs break-all">
                    {c.redirect_uris.join(', ')}
                  </p>
                </div>
                {canEdit && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPendingDelete(c)}
                    className="shrink-0"
                  >
                    <Trash2 className="mr-2 h-4 w-4" aria-hidden />
                    Delete
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <Dialog open={open} onOpenChange={(v) => !saving && setOpen(v)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register an application</DialogTitle>
            <DialogDescription>
              Return addresses must be https, or http on 127.0.0.1, [::1] or localhost (any port)
              for applications that run on a computer.
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="mcp-client-name">Name</Label>
                <Input
                  id="mcp-client-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mcp-client-uris">Return addresses (redirect URIs)</Label>
                <Textarea
                  id="mcp-client-uris"
                  rows={3}
                  value={uris}
                  onChange={(e) => setUris(e.target.value)}
                  placeholder={
                    'http://127.0.0.1:33418/callback\nhttps://assistant.example.com/oauth/callback'
                  }
                />
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={saving}>
              Cancel
            </Button>
            <Button onClick={() => void create()} disabled={saving || !name.trim() || !uris.trim()}>
              {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
              Register
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(v) => !v && !saving && setPendingDelete(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {pendingDelete?.name}?</AlertDialogTitle>
            <AlertDialogDescription>
              Every connection made with it ends at once.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={saving}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void remove()
              }}
              disabled={saving}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
