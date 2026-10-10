'use client'

/**
 * Generate an API key: name, expiry and scopes, then the one-time reveal.
 * Used for your own keys (settings/api-keys) and for a service account's keys
 * (settings/service-accounts); the caller decides where the key is minted.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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
import { getErrorMessage } from '@/lib/api/error-handler'
import { copyToClipboard } from '@/lib/clipboard'
import { API_KEY_EXPIRY_OPTIONS, DEFAULT_API_KEY_EXPIRY_DAYS } from '../lib/expiry'
import type { CreateAPIKeyRequest } from '../types/api-key.types'

/** Scopes offered when minting a key. The API refuses one the caller lacks. */
export const API_KEY_SCOPES = [
  'assets:read',
  'findings:read',
  'scans:read',
  'integrations:read',
  'assets:write',
  'findings:write',
  'scans:write',
]

const DEFAULT_SCOPES = ['assets:read', 'findings:read']

export function GenerateKeyDialog({
  open,
  onOpenChange,
  onSubmit,
  onCreated,
  isMutating,
  title = 'Generate API key',
  description = 'Scope the key to the minimum permissions needed. The secret is shown once.',
  namePlaceholder = 'Nightly export script',
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  /** Mints the key; resolves to the API response carrying the plaintext once. */
  onSubmit: (req: CreateAPIKeyRequest) => Promise<{ key?: string } | undefined>
  onCreated: (plaintext: string) => void
  isMutating: boolean
  title?: string
  description?: string
  namePlaceholder?: string
}) {
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [expires, setExpires] = useState<string>(DEFAULT_API_KEY_EXPIRY_DAYS)
  const [scopes, setScopes] = useState<string[]>(DEFAULT_SCOPES)

  function toggleScope(s: string) {
    setScopes((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]))
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name) return toast.error('Name is required')
    if (scopes.length === 0) return toast.error('Select at least one scope')
    try {
      const res = await onSubmit({
        name,
        description: desc || undefined,
        scopes,
        expires_in_days: Number(expires),
      })
      onCreated(res?.key ?? '')
      onOpenChange(false)
      setName('')
      setDesc('')
      setExpires(DEFAULT_API_KEY_EXPIRY_DAYS)
      setScopes(DEFAULT_SCOPES)
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to create the API key'))
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogForm onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="key-name">Name</Label>
              <Input
                id="key-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={namePlaceholder}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="key-desc">Description (optional)</Label>
              <Input id="key-desc" value={desc} onChange={(e) => setDesc(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="key-expiry">Expires</Label>
              <Select value={expires} onValueChange={setExpires}>
                <SelectTrigger id="key-expiry">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {API_KEY_EXPIRY_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Scopes</Label>
              <div className="grid grid-cols-2 gap-2">
                {API_KEY_SCOPES.map((s) => (
                  <label key={s} className="flex items-center gap-2 text-sm">
                    <Checkbox checked={scopes.includes(s)} onCheckedChange={() => toggleScope(s)} />
                    <span className="font-mono text-xs">{s}</span>
                  </label>
                ))}
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={isMutating}>
              {isMutating ? 'Generating...' : 'Generate'}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

/** Shows a freshly minted key once, with a copy button. */
export function RevealKeyDialog({ value, onClose }: { value: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    await copyToClipboard(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <Dialog open={!!value} onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>Copy your API key</DialogTitle>
          <DialogDescription>
            This is the only time the full key is shown. Store it securely.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="bg-muted flex items-center gap-2 rounded-md p-3">
            <code className="flex-1 break-all text-xs">{value}</code>
            <Button size="icon" variant="ghost" onClick={copy} title="Copy" aria-label="Copy key">
              {copied ? <Check className="h-4 w-4 text-success" /> : <Copy className="h-4 w-4" />}
            </Button>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button onClick={onClose}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
