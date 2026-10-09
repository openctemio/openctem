'use client'

/**
 * Put something out of scope (RFC-054 §6.2): an exclusion scans never touch,
 * even inside an in-scope entry. A new exclusion waits for another approver
 * (the requester cannot approve their own), so a single account cannot hide
 * a system from scans unnoticed. Kind is detected from the pattern; `*.x`
 * covers x and every name below it, as for entries.
 *
 * "Only a path" turns it into a web rule (RFC-056 §5): the hosts stay in
 * scope and only requests under the path prefix (for the chosen methods,
 * empty: every method) are blocked. Its testing mode starts Blocked.
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
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { createScopeExclusion, invalidateScopeCache } from '../api/use-scope-api'
import { scopeErrorMessage } from '../lib/scope-codes'
import { coversText } from '../lib/scope-entry'
import {
  HTTP_METHODS,
  methodsText,
  pathPrefixProblem,
  STATE_CHANGING_METHODS,
} from '../lib/path-exclusion'
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
  const [pathOnly, setPathOnly] = useState(false)
  const [pathPrefix, setPathPrefix] = useState('')
  const [methods, setMethods] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!open) return
    setPathOnly(false)
    setPathPrefix('')
    setMethods([])
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
    if (pathOnly) {
      const host = pattern || '*'
      const hostKind = host === '*' ? 'domain' : detectScopeKind(host)
      if (hostKind !== 'domain' && hostKind !== 'url')
        return setError(
          'A path rule applies to hosts: enter a domain, *.domain, a URL origin or leave it empty for every host.'
        )
      const problem = pathPrefixProblem(pathPrefix)
      if (problem) return setError(problem)
    } else if (!pattern) return setError('Enter what scans must never touch.')
    if (!pathOnly && !override && !detected)
      return setError(
        'This is not a domain, IP address, IP range, URL or repository. Pick its kind.'
      )
    if (!pathOnly && !(EXCLUSION_KINDS as string[]).includes(kind))
      return setError('Exclusions cover domains, addresses, URLs and repositories.')
    if (!reason.trim()) return setError(t('scope.error.REASON_REQUIRED'))
    if (days.trim() && (!Number.isFinite(n) || n < 1 || n > MAX_DAYS))
      return setError(`Days must be between 1 and ${MAX_DAYS}.`)
    setSaving(true)
    setError(null)
    try {
      const ex = await createScopeExclusion({
        ...(pathOnly
          ? {
              exclusion_type: 'path',
              pattern: pattern || '*',
              path_prefix: pathPrefix.trim(),
              ...(methods.length > 0 ? { methods } : {}),
            }
          : { exclusion_type: kind, pattern }),
        reason: reason.trim(),
        ...(n > 0 ? { expires_at: daysFromNow(n) } : {}),
      })
      await invalidateScopeCache()
      const label = pathOnly ? `${pattern || '*'}${pathPrefix.trim()}` : pattern
      toast.success(
        ex?.status === 'active'
          ? `${label} is out of scope`
          : `${label} waits for another approver`,
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
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Put out of scope</DialogTitle>
          <DialogDescription>
            Scans never touch what you list here, even inside an in-scope entry: fragile production
            hosts, partners&apos; systems, payment gateways.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form id={id} onSubmit={submit} className="space-y-4">
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
                placeholder={
                  pathOnly ? '*.example.com (empty: every host)' : SCOPE_KIND_PLACEHOLDER[kind]
                }
                onChange={(e) => {
                  setWhat(e.target.value)
                  setError(null)
                }}
              />
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                {pathOnly ? (
                  <span>The hosts the path rule applies to; they stay in scope.</span>
                ) : override ? (
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
            <div className="space-y-3 rounded-md border p-3">
              <div className="flex items-start gap-2">
                <Checkbox
                  id={`${id}-path`}
                  checked={pathOnly}
                  onCheckedChange={(v) => {
                    setPathOnly(v === true)
                    setError(null)
                  }}
                  className="mt-0.5"
                />
                <Label htmlFor={`${id}-path`} className="flex-col items-start gap-0.5 font-normal">
                  <span className="block font-medium">Only a path</span>
                  <span className="block text-xs text-muted-foreground">
                    Block requests under a path (for example /admin or /api/payments) and keep the
                    rest of the host in scope.
                  </span>
                </Label>
              </div>
              {pathOnly && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor={`${id}-prefix`}>Path prefix</Label>
                    <Input
                      id={`${id}-prefix`}
                      value={pathPrefix}
                      autoComplete="off"
                      spellCheck={false}
                      placeholder="/admin"
                      onChange={(e) => {
                        setPathPrefix(e.target.value)
                        setError(null)
                      }}
                    />
                    <p className="text-xs text-muted-foreground">
                      Covers the path and everything below it. * stands for one whole segment.
                    </p>
                  </div>
                  <fieldset className="space-y-2">
                    <legend className="text-sm font-medium">Methods blocked</legend>
                    <div className="flex flex-wrap gap-x-4 gap-y-2">
                      {HTTP_METHODS.map((m) => (
                        <label key={m} className="flex items-center gap-1.5 text-sm">
                          <Checkbox
                            checked={methods.includes(m)}
                            onCheckedChange={(v) =>
                              setMethods((cur) =>
                                v === true ? [...cur, m] : cur.filter((x) => x !== m)
                              )
                            }
                          />
                          {m}
                        </label>
                      ))}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Now: {methodsText(methods)}.{' '}
                      <button
                        type="button"
                        className="underline underline-offset-2 hover:text-foreground"
                        onClick={() => setMethods(STATE_CHANGING_METHODS)}
                      >
                        Block only what changes state
                      </button>{' '}
                      so read-only checks still run there.
                    </p>
                  </fieldset>
                  <p className="text-xs text-muted-foreground">
                    Testing starts Blocked. An exclusion approver can later allow read-only or full
                    testing for a limited time.
                  </p>
                </>
              )}
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
        </DialogBody>
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
