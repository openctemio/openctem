'use client'

/**
 * Put something out of scope (RFC-054 §6.2): an exclusion scans never touch,
 * even inside an in-scope entry. A new exclusion waits for another approver
 * (the requester cannot approve their own), so a single account cannot hide
 * a system from scans unnoticed. Kind is detected from the pattern; `*.x`
 * covers x and every name below it, as for entries.
 */

import { useEffect, useId, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
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
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { createScopeExclusion, invalidateScopeCache } from '../api/use-scope-api'
import { scopeErrorMessage } from '../lib/scope-codes'
import { coversText } from '../lib/scope-entry'
import {
  detectScopeKind,
  EXCLUSION_KINDS,
  SCOPE_KIND_LABEL,
  SCOPE_KIND_PLACEHOLDER,
  ScopeTargetTypeSelect,
  type ScopeKind,
} from './scope-target-type'

const MAX_DAYS = 365

/** An ISO time n days from now (an event-time helper, not render). */
export function daysFromNow(n: number, now: number = Date.now()): string {
  return new Date(now + n * 86_400_000).toISOString()
}

interface ScopeExclusionDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ScopeExclusionDialog({ open, onOpenChange }: ScopeExclusionDialogProps) {
  const { t } = useTranslation()
  const id = useId()
  const [what, setWhat] = useState('')
  const [override, setOverride] = useState<ScopeKind | null>(null)
  const [reason, setReason] = useState('')
  const [days, setDays] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!open) return
    setWhat('')
    setOverride(null)
    setReason('')
    setDays('')
    setError(null)
  }, [open])

  const detected = detectScopeKind(what)
  const kind: ScopeKind = override ?? detected ?? 'domain'
  const pattern = what.trim()
  const n = days.trim() ? Math.round(Number(days)) : 0

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!pattern) return setError('Enter what scans must never touch.')
    if (!override && !detected)
      return setError(
        'This is not a domain, IP address, IP range, URL or repository. Pick its kind.'
      )
    if (!(EXCLUSION_KINDS as string[]).includes(kind))
      return setError('Exclusions cover domains, addresses, URLs and repositories.')
    if (!reason.trim()) return setError(t('scope.error.REASON_REQUIRED'))
    if (days.trim() && (!Number.isFinite(n) || n < 1 || n > MAX_DAYS))
      return setError(`Days must be between 1 and ${MAX_DAYS}.`)
    setSaving(true)
    setError(null)
    try {
      const ex = await createScopeExclusion({
        exclusion_type: kind,
        pattern,
        reason: reason.trim(),
        ...(n > 0 ? { expires_at: daysFromNow(n) } : {}),
      })
      await invalidateScopeCache()
      toast.success(
        ex?.status === 'active'
          ? `${pattern} is out of scope`
          : `${pattern} waits for another approver`,
        ex?.status === 'active'
          ? undefined
          : { description: 'Scans keep reaching it until the exclusion is approved.' }
      )
      onOpenChange(false)
    } catch (err) {
      setError(scopeErrorMessage(t, err, 'Could not add the exclusion.'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90dvh] flex-col sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Put out of scope</DialogTitle>
          <DialogDescription>
            Scans never touch what you list here, even inside an in-scope entry: fragile production
            hosts, partners&apos; systems, payment gateways.
          </DialogDescription>
        </DialogHeader>
        <form
          id={id}
          onSubmit={submit}
          className="-mx-6 min-h-0 flex-1 space-y-4 overflow-y-auto px-6 py-1"
        >
          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor={`${id}-what`}>What</Label>
            <Input
              id={`${id}-what`}
              value={what}
              autoComplete="off"
              spellCheck={false}
              placeholder={SCOPE_KIND_PLACEHOLDER[kind]}
              onChange={(e) => {
                setWhat(e.target.value)
                setError(null)
              }}
            />
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {override ? (
                <>
                  <span>Kind:</span>
                  <ScopeTargetTypeSelect
                    value={override}
                    onValueChange={(v) => setOverride(v as ScopeKind)}
                    only={EXCLUSION_KINDS}
                    className="h-7 w-44 text-xs"
                    aria-label="Kind"
                  />
                </>
              ) : (
                <>
                  <span aria-live="polite">
                    {pattern
                      ? detected
                        ? `Detected: ${SCOPE_KIND_LABEL[detected]} · covers ${coversText({ pattern, target_type: detected })}`
                        : 'Kind not recognised'
                      : 'A domain (*.x covers x and every name below it), IP address or range, URL or repository.'}
                  </span>
                  {pattern && (
                    <button
                      type="button"
                      className="underline underline-offset-2 hover:text-foreground"
                      onClick={() => setOverride(detected ?? 'domain')}
                    >
                      {detected ? 'Change' : 'Pick the kind'}
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-reason`}>Reason</Label>
            <Textarea
              id={`${id}-reason`}
              rows={2}
              maxLength={1000}
              value={reason}
              placeholder="Why must scans never touch it? For example: payment gateway, PCI change freeze."
              onChange={(e) => {
                setReason(e.target.value)
                setError(null)
              }}
            />
            <p className="text-xs text-muted-foreground">Required. Kept in the audit log.</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-days`}>Ends after (days, optional)</Label>
            <Input
              id={`${id}-days`}
              type="number"
              min={1}
              max={MAX_DAYS}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              className="w-28"
            />
            <p className="text-xs text-muted-foreground">Empty: until someone lifts it.</p>
          </div>
          <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
            Another approver must approve it before scans start skipping it.
          </p>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          <Button type="submit" form={id} disabled={saving}>
            {saving && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            Request exclusion
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
