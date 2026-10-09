'use client'

/**
 * Verify a seed's domain with a DNS TXT record (research/22 P0-10). The
 * organization proves it controls the domain; names under it are then
 * attributed with the strong "verified root" rule and confirmed without
 * review. This verification is for EASM only: it never lets anyone sign in
 * (SSO domains are set up by a platform administrator).
 *
 * The server is the boundary: it normalizes the domain, refuses public
 * suffixes and shared consumer domains, takes the tenant from the session,
 * limits checks to 10 per hour and audits every step.
 */

import { useState } from 'react'
import { BadgeCheck, Copy, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import type { EASMVerifiedDomain } from '@/lib/api/generated'
import { getErrorMessage } from '@/lib/api/error-handler'
import { addVerifiedDomain, checkVerifiedDomain } from '../hooks/use-easm-verified-domains'

function CopyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="flex items-center gap-1">
        <code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1 font-mono text-xs">
          {value}
        </code>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="h-7 w-7 shrink-0"
          aria-label={`Copy ${label.toLowerCase()}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value)
              toast.success(`${label} copied`)
            } catch {
              toast.error('Could not copy')
            }
          }}
        >
          <Copy className="h-3.5 w-3.5" aria-hidden />
        </Button>
      </div>
    </div>
  )
}

export interface VerifyDomainDialogProps {
  /** The seed's root domain. */
  domain: string | null
  /** The organization's existing row for it, if any. */
  existing?: EASMVerifiedDomain
  onOpenChange: (open: boolean) => void
  /** Called after the row changed (added or checked). */
  onChanged: () => void
}

export function VerifyDomainDialog({
  domain,
  existing,
  onOpenChange,
  onChanged,
}: VerifyDomainDialogProps) {
  const [row, setRow] = useState<EASMVerifiedDomain | undefined>(existing)
  const [busy, setBusy] = useState(false)
  const current = row ?? existing

  const start = async () => {
    if (!domain) return
    setBusy(true)
    try {
      const created = await addVerifiedDomain(domain)
      setRow(created)
      onChanged()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Could not start verification'))
    } finally {
      setBusy(false)
    }
  }

  const check = async () => {
    if (!current?.id) return
    setBusy(true)
    try {
      const checked = await checkVerifiedDomain(current.id)
      setRow(checked)
      onChanged()
      if (checked.status === 'verified') {
        toast.success(`${checked.domain} is verified`)
      } else {
        toast.info('The TXT record was not found yet. DNS changes can take a while to appear.')
      }
    } catch (e) {
      toast.error(getErrorMessage(e, 'Could not check the record'))
    } finally {
      setBusy(false)
    }
  }

  const verified = current?.status === 'verified'
  return (
    <Dialog
      open={!!domain}
      onOpenChange={(open) => {
        if (!open) setRow(undefined)
        onOpenChange(open)
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Verify {domain}</DialogTitle>
          <DialogDescription>
            Prove your organization controls this domain with a DNS TXT record. Names found under a
            verified domain are confirmed as yours without review. This is for attack-surface
            management only and never lets anyone sign in.
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="grid gap-4">
          {!current && (
            <p className="text-sm text-muted-foreground">
              Start verification to get the TXT record to publish at your DNS provider.
            </p>
          )}

          {current?.managed && (
            <p className="text-sm text-muted-foreground">
              This domain was set up by your platform administrator and is managed there.
            </p>
          )}

          {current && !current.managed && current.instructions && (
            <div className="space-y-3">
              {verified ? (
                <p className="flex items-center gap-1 text-sm text-success">
                  <BadgeCheck className="h-4 w-4" aria-hidden /> Verified. It is re-checked every 12
                  hours; keep the record in place.
                </p>
              ) : (
                <p className="text-sm">
                  {current.status === 'failed'
                    ? 'The record is gone, so names under this domain no longer confirm automatically. Publish it again, then check.'
                    : 'Publish this TXT record, then check. You can run up to 10 checks an hour.'}
                </p>
              )}
              <CopyValue label="Host" value={current.instructions.host ?? ''} />
              <CopyValue label="Value" value={current.instructions.value ?? ''} />
            </div>
          )}
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Close
          </Button>
          {!current && (
            <Button onClick={() => void start()} disabled={busy}>
              Start verification
            </Button>
          )}
          {current && !current.managed && !verified && (
            <Button onClick={() => void check()} disabled={busy}>
              <RefreshCw className="me-2 h-4 w-4" aria-hidden />
              Check now
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
