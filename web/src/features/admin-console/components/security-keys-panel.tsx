'use client'

import { useId, useState, type FormEvent } from 'react'
import {
  CheckCircle2,
  Copy,
  Download,
  KeyRound,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, RelativeTime } from '@/features/shared'
import {
  generateRecoveryCodes,
  registerSecurityKey,
  removeSecurityKey,
  renameSecurityKey,
  useConsoleFactors,
  type ConsoleAuthenticator,
  type ConsoleFactors,
} from '../api/use-console-factors'
import { isWebAuthnSupported } from '../lib/webauthn'
import { securityKeyErrorMessage } from '../lib/security-key-errors'

const NAME_MAX = 64

/**
 * Security > My security keys: the signed-in administrator's own keys and
 * passkeys, and their recovery codes (RFC-078 §7). Adding a key, removing one
 * and new recovery codes each take a step-up (the console's step-up dialog).
 * `enrollment` is the shell's enrollment gate: only registering keys and
 * recovery codes is allowed there, so rename and remove are hidden.
 */
export function SecurityKeysPanel({
  enrollment = false,
  onChanged,
}: {
  enrollment?: boolean
  /** After any change (the enrollment gate re-checks the session). */
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useConsoleFactors()
  const [adding, setAdding] = useState(false)
  const [renaming, setRenaming] = useState<ConsoleAuthenticator | null>(null)
  const [removing, setRemoving] = useState<ConsoleAuthenticator | null>(null)
  const [confirmRegenerate, setConfirmRegenerate] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [codes, setCodes] = useState<string[] | null>(null)

  const changed = async () => {
    await mutate()
    onChanged?.()
  }

  const generate = async () => {
    setGenerating(true)
    try {
      const res = await generateRecoveryCodes()
      setConfirmRegenerate(false)
      setCodes(res.codes)
      await changed()
    } catch (err) {
      toast.error(securityKeyErrorMessage(err, t))
    } finally {
      setGenerating(false)
    }
  }

  if (error) {
    return (
      <ErrorState
        title={t('admin.keys.title', 'My security keys')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    )
  }

  const supported = isWebAuthnSupported()
  const keys = data.authenticators ?? []
  const canAdd = data.webauthn_enabled && supported && keys.length < data.max_authenticators

  return (
    <div className="space-y-4">
      <PolicyState factors={data} />

      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyRound className="size-4 text-muted-foreground" />
              {t('admin.keys.listTitle', 'Security keys and passkeys')}
            </CardTitle>
            <CardDescription>
              {t(
                'admin.keys.listDescription',
                'Used to sign in to this console and to confirm sensitive actions. At most {max} keys.',
                { max: data.max_authenticators }
              )}
            </CardDescription>
          </div>
          <Button onClick={() => setAdding(true)} disabled={!canAdd} className="w-full sm:w-auto">
            <Plus className="me-1.5 size-4" />
            {t('admin.keys.add', 'Add security key')}
          </Button>
        </CardHeader>
        <CardContent className="space-y-3">
          {!supported && data.webauthn_enabled && (
            <Alert variant="destructive">
              <AlertDescription>
                {t(
                  'admin.keys.unsupported',
                  'This browser cannot use security keys or passkeys. Use a current browser.'
                )}
              </AlertDescription>
            </Alert>
          )}
          {keys.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('admin.keys.empty', 'No security key registered yet.')}
            </p>
          ) : (
            <ul className="divide-y rounded-md border">
              {keys.map((k) => (
                <li
                  key={k.id}
                  className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium break-all">{k.name}</span>
                      {k.synced ? (
                        <Badge variant="secondary">
                          {t('admin.keys.synced', 'Synced passkey')}
                        </Badge>
                      ) : (
                        <Badge variant="outline">
                          {t('admin.keys.deviceBound', 'Device-bound')}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {t('admin.keys.added', 'Added')} <RelativeTime date={k.created_at} />
                      {' · '}
                      {k.last_used_at ? (
                        <>
                          {t('admin.keys.lastUsed', 'Last used')}{' '}
                          <RelativeTime date={k.last_used_at} />
                        </>
                      ) : (
                        t('admin.keys.neverUsed', 'Never used')
                      )}
                    </p>
                  </div>
                  {!enrollment && (
                    <div className="flex shrink-0 gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setRenaming(k)}
                        aria-label={t('admin.keys.renameLabel', 'Rename {name}', { name: k.name })}
                      >
                        <Pencil className="me-1.5 size-3.5" />
                        {t('admin.keys.rename', 'Rename')}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setRemoving(k)}
                        aria-label={t('admin.keys.removeLabel', 'Remove {name}', { name: k.name })}
                      >
                        <Trash2 className="me-1.5 size-3.5" />
                        {t('admin.keys.remove', 'Remove')}
                      </Button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1.5">
            <CardTitle className="text-base">
              {t('admin.keys.recoveryTitle', 'Recovery codes')}
            </CardTitle>
            <CardDescription>
              {t(
                'admin.keys.recoveryDescription',
                'One-time codes for signing in when no key is at hand. They never confirm a sensitive action.'
              )}
            </CardDescription>
          </div>
          <Button
            variant="outline"
            className="w-full sm:w-auto"
            disabled={generating}
            onClick={() =>
              data.recovery_codes_left > 0 ? setConfirmRegenerate(true) : void generate()
            }
          >
            {generating ? (
              <Loader2 className="me-1.5 size-4 animate-spin" />
            ) : (
              <RefreshCw className="me-1.5 size-4" />
            )}
            {data.recovery_codes_left > 0
              ? t('admin.keys.regenerate', 'Generate new codes')
              : t('admin.keys.generate', 'Generate recovery codes')}
          </Button>
        </CardHeader>
        <CardContent>
          <p className="text-sm" data-testid="recovery-codes-left">
            {data.recovery_codes_left > 0
              ? t('admin.keys.codesLeft', '{count} unused codes left.', {
                  count: data.recovery_codes_left,
                })
              : t('admin.keys.noCodes', 'You have no unused recovery codes.')}
          </p>
        </CardContent>
      </Card>

      <AddKeyDialog
        open={adding}
        onOpenChange={setAdding}
        onAdded={async () => {
          setAdding(false)
          toast.success(t('admin.keys.addedToast', 'Security key added'))
          await changed()
        }}
      />
      <RenameKeyDialog
        target={renaming}
        onClose={() => setRenaming(null)}
        onRenamed={async () => {
          setRenaming(null)
          await changed()
        }}
      />
      <RemoveKeyDialog
        target={removing}
        onClose={() => setRemoving(null)}
        onRemoved={async () => {
          setRemoving(null)
          toast.success(t('admin.keys.removedToast', 'Security key removed'))
          await changed()
        }}
      />
      <ConfirmDialog
        open={confirmRegenerate}
        onOpenChange={(open) => !generating && setConfirmRegenerate(open)}
        title={t('admin.keys.regenerateTitle', 'Replace your recovery codes?')}
        desc={t(
          'admin.keys.regenerateDesc',
          'Your current recovery codes stop working. Save the new ones before you close the next window.'
        )}
        confirmText={t('admin.keys.regenerateConfirm', 'Generate new codes')}
        isLoading={generating}
        handleConfirm={() => void generate()}
      />
      <RecoveryCodesDialog codes={codes} onDone={() => setCodes(null)} />
    </div>
  )
}

/** The policy and what this administrator still needs. */
function PolicyState({ factors }: { factors: ConsoleFactors }) {
  const { t } = useTranslation()
  if (!factors.webauthn_enabled) {
    return (
      <Alert>
        <ShieldAlert className="size-4" />
        <AlertTitle>
          {t('admin.keys.unavailableTitle', 'Security keys are not available')}
        </AlertTitle>
        <AlertDescription>
          {t(
            'admin.keys.notConfigured',
            'Security keys are not available: the console address (ADMIN_PUBLIC_URL) is not set.'
          )}
        </AlertDescription>
      </Alert>
    )
  }
  const keys = factors.authenticators?.length ?? 0
  const compliant = keys >= factors.min_authenticators && factors.recovery_codes_left > 0
  return (
    <Alert variant={factors.enrollment_required ? 'destructive' : 'default'}>
      {compliant ? <ShieldCheck className="size-4" /> : <ShieldAlert className="size-4" />}
      <AlertTitle>
        {factors.require_webauthn
          ? t('admin.keys.policyOn', 'This console requires security keys')
          : t('admin.keys.policyOff', 'Security keys are recommended')}
      </AlertTitle>
      <AlertDescription className="space-y-2">
        <p>
          {t(
            'admin.keys.guidance',
            'Register at least {min} keys (one is a spare) and keep unused recovery codes, so a lost key never locks you out.',
            { min: factors.min_authenticators }
          )}
        </p>
        <ul className="space-y-1 text-sm">
          <li className="flex items-center gap-2">
            <StatusDot ok={keys >= factors.min_authenticators} />
            {t('admin.keys.keysStatus', 'Security keys: {count} of {min}', {
              count: keys,
              min: factors.min_authenticators,
            })}
          </li>
          <li className="flex items-center gap-2">
            <StatusDot ok={factors.recovery_codes_left > 0} />
            {t('admin.keys.codesStatus', 'Unused recovery codes: {count}', {
              count: factors.recovery_codes_left,
            })}
          </li>
        </ul>
        {factors.require_webauthn && keys > 0 && !factors.totp_allowed && (
          <p>
            {t(
              'admin.keys.totpRefused',
              'The authenticator app is no longer accepted for your account: sign in and confirm with a key, or with a recovery code at sign-in.'
            )}
          </p>
        )}
      </AlertDescription>
    </Alert>
  )
}

function StatusDot({ ok }: { ok: boolean }) {
  return ok ? (
    <CheckCircle2 className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden />
  ) : (
    <ShieldAlert className="size-4 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden />
  )
}

function AddKeyDialog({
  open,
  onOpenChange,
  onAdded,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onAdded: () => Promise<void>
}) {
  const { t } = useTranslation()
  const nameId = useId()
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const close = (next: boolean) => {
    if (busy) return
    if (!next) {
      setName('')
      setError(null)
    }
    onOpenChange(next)
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const trimmed = name.trim()
    if (!trimmed) return
    setBusy(true)
    setError(null)
    try {
      await registerSecurityKey(trimmed)
      setName('')
      setBusy(false)
      await onAdded()
    } catch (err) {
      setError(securityKeyErrorMessage(err, t))
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t('admin.keys.addTitle', 'Add a security key or passkey')}</DialogTitle>
            <DialogDescription>
              {t(
                'admin.keys.addDescription',
                'Name it so you can tell your keys apart. You confirm it is you first, then your browser asks you to touch the key or use your fingerprint, face or PIN.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor={nameId}>{t('admin.keys.name', 'Name')}</Label>
              <Input
                id={nameId}
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={NAME_MAX}
                placeholder={t('admin.keys.namePlaceholder', 'e.g. Blue USB key, Work laptop')}
                autoFocus
                required
              />
            </div>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => close(false)} disabled={busy}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={busy || !name.trim()}>
              {busy && <Loader2 className="me-2 size-4 animate-spin" />}
              {t('admin.keys.addConfirm', 'Continue')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

function RenameKeyDialog({
  target,
  onClose,
  onRenamed,
}: {
  target: ConsoleAuthenticator | null
  onClose: () => void
  onRenamed: () => Promise<void>
}) {
  const { t } = useTranslation()
  const nameId = useId()
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [shownFor, setShownFor] = useState<string | null>(null)

  // Prefill when a new key is picked (state adjusted during render).
  if (target && shownFor !== target.id) {
    setShownFor(target.id)
    setName(target.name)
    setError(null)
  }
  if (!target && shownFor !== null) setShownFor(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!target || !name.trim()) return
    setBusy(true)
    setError(null)
    try {
      await renameSecurityKey(target.id, name.trim())
      setBusy(false)
      await onRenamed()
    } catch (err) {
      setError(securityKeyErrorMessage(err, t))
      setBusy(false)
    }
  }

  return (
    <Dialog open={!!target} onOpenChange={(next) => !next && !busy && onClose()}>
      <DialogContent>
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t('admin.keys.renameTitle', 'Rename security key')}</DialogTitle>
          </DialogHeader>
          <DialogBody className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor={nameId}>{t('admin.keys.name', 'Name')}</Label>
              <Input
                id={nameId}
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={NAME_MAX}
                autoFocus
                required
              />
            </div>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={busy || !name.trim()}>
              {busy && <Loader2 className="me-2 size-4 animate-spin" />}
              {t('admin.keys.save', 'Save')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

function RemoveKeyDialog({
  target,
  onClose,
  onRemoved,
}: {
  target: ConsoleAuthenticator | null
  onClose: () => void
  onRemoved: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const remove = async () => {
    if (!target) return
    setBusy(true)
    setError(null)
    try {
      await removeSecurityKey(target.id)
      setBusy(false)
      await onRemoved()
    } catch (err) {
      setError(securityKeyErrorMessage(err, t))
      setBusy(false)
    }
  }

  return (
    <ConfirmDialog
      open={!!target}
      onOpenChange={(open) => {
        if (busy) return
        if (!open) {
          setError(null)
          onClose()
        }
      }}
      destructive
      title={t('admin.keys.removeTitle', 'Remove this security key?')}
      desc={t(
        'admin.keys.removeDesc',
        '"{name}" can no longer sign in to this console or confirm actions. You confirm it is you first.',
        { name: target?.name ?? '' }
      )}
      confirmText={t('admin.keys.removeConfirm', 'Remove key')}
      isLoading={busy}
      handleConfirm={() => void remove()}
    >
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </ConfirmDialog>
  )
}

/**
 * New recovery codes, shown once: copy or download them, and acknowledge
 * before the dialog closes. They are not kept anywhere in the browser.
 */
function RecoveryCodesDialog({ codes, onDone }: { codes: string[] | null; onDone: () => void }) {
  const { t } = useTranslation()
  const ackId = useId()
  const [acked, setAcked] = useState(false)

  const text = (codes ?? []).join('\n')

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      toast.success(t('admin.keys.copied', 'Recovery codes copied'))
    } catch {
      toast.error(t('admin.keys.copyFailed', 'Could not copy; select the codes and copy them.'))
    }
  }

  const download = () => {
    if (typeof URL.createObjectURL !== 'function') return
    const url = URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'openctem-console-recovery-codes.txt'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  const done = () => {
    setAcked(false)
    onDone()
  }

  return (
    <Dialog open={!!codes} onOpenChange={(next) => !next && acked && done()}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t('admin.keys.codesTitle', 'Save your recovery codes')}</DialogTitle>
          <DialogDescription>
            {t(
              'admin.keys.codesDescription',
              'This is the only time they are shown. Each code signs you in once when no key is at hand. Keep them somewhere safe, away from your keys.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <ul
            className="grid grid-cols-1 gap-2 rounded-md border bg-muted p-3 font-mono text-sm sm:grid-cols-2"
            aria-label={t('admin.keys.recoveryTitle', 'Recovery codes')}
          >
            {(codes ?? []).map((c) => (
              <li key={c} className="break-all select-all">
                {c}
              </li>
            ))}
          </ul>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button type="button" variant="outline" onClick={() => void copy()}>
              <Copy className="me-1.5 size-4" />
              {t('admin.keys.copy', 'Copy')}
            </Button>
            <Button type="button" variant="outline" onClick={download}>
              <Download className="me-1.5 size-4" />
              {t('admin.keys.download', 'Download .txt')}
            </Button>
          </div>
          <div className="flex items-start gap-2">
            <Checkbox id={ackId} checked={acked} onCheckedChange={(v) => setAcked(v === true)} />
            <Label htmlFor={ackId} className="leading-snug font-normal">
              {t('admin.keys.ack', 'I saved these codes somewhere safe')}
            </Label>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button type="button" disabled={!acked} onClick={done}>
            {t('admin.keys.done', 'Done')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
