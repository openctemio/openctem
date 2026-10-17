'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { AlertCircle, Check, Copy, Info, Loader2, Mail, Send, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
  DialogForm,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { useRoles } from '@/features/access-control/api/use-roles'
import { ApiClientError } from '@/lib/api/error-handler'
import { copyToClipboard } from '@/lib/clipboard'
import { invitationLink } from '@/features/auth/lib/invitation-token'

import { createTenantInvitation, previewInvitation } from '../api/use-members'
import { useGroups } from '@/features/access-control/api/use-groups'
import { TeamPicker } from './team-picker'
import type { InvitationPreview } from '../types/member.types'
import { dateInputDaysFromNow, endOfDayISO } from '../lib/external-access'
import { RolePicker, defaultViewerRoleId } from './role-checklist'

/**
 * `${origin}/invitations#token=<token>`: the page the invitee opens to join.
 * The token is in the fragment, which the browser never sends to a server.
 */
export function buildInvitationLink(token: string, origin?: string): string {
  const base = origin ?? (typeof window !== 'undefined' ? window.location.origin : '')
  return invitationLink(base, token)
}

/** Refusal and error codes the dialog explains in words (api RFC-095). */
const KNOWN_CODES = new Set([
  'INVALID_EMAIL',
  'INVITEE_NOT_ON_VERIFIED_DOMAIN',
  'INVITEE_DOMAIN_NOT_ALLOWED',
  'PERSONAL_ACCOUNTS_BLOCKED',
  'ABOVE_TRUST_CEILING',
  'ALREADY_MEMBER',
  'ALREADY_INVITED',
  'ROLE_NOT_GRANTABLE',
  'TEAM_NOT_GRANTABLE',
  'ADMIN_NEEDS_OWNER',
  'INVITATIONS_RATE_LIMITED',
  'LIMIT_REACHED',
  'STEP_UP_FAILED',
])

const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

interface InviteUserDialogProps {
  tenantSlug: string | undefined
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Only the owner may make someone an administrator (settings decision B2). */
  canGrantAdmin?: boolean
  /** Called after the invitation is created (refresh the invitation list). */
  onInvited?: () => void
}

/**
 * Invite someone by email, to one primary role and optional additional roles.
 * While the inviter types, the API previews what will happen (inside or
 * outside the organization, re-authentication, two-factor, end of access), so
 * the rules show up as guidance before anything is sent.
 *
 * The API stores only a hash of the invitation token, so the usable link
 * exists once: in the response to the create request. It is shown here and
 * never again.
 */
export function InviteUserDialog({
  tenantSlug,
  open,
  onOpenChange,
  onInvited,
  canGrantAdmin = false,
}: InviteUserDialogProps) {
  const { t } = useTranslation()
  const [email, setEmail] = useState('')
  const [roleIds, setRoleIds] = useState<string[]>([])
  const [groupIds, setGroupIds] = useState<string[]>([])
  const [seeded, setSeeded] = useState(false)
  const [accessEnds, setAccessEnds] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<InvitationPreview | null>(null)
  const [link, setLink] = useState<{
    email: string
    url: string | null
    lookalikeOf?: string[]
    accessExpiresAt?: string
    outside: boolean
    mfaRequired: boolean
  } | null>(null)
  const [copied, setCopied] = useState(false)
  const previewSeq = useRef(0)

  const { roles, isLoading: rolesLoading } = useRoles({ skip: !open })
  const { groups: teams, isLoading: teamsLoading } = useGroups(undefined, open)
  const viewerId = defaultViewerRoleId(roles)
  if (open && !seeded && viewerId) {
    setSeeded(true)
    setRoleIds([viewerId])
  }

  const trimmed = email.trim()
  const emailLooksValid = EMAIL_SHAPE.test(trimmed)

  // Preview what this invitation would do (debounced). A stale answer for an
  // earlier value is dropped.
  useEffect(() => {
    if (!open || !emailLooksValid || roleIds.length === 0) {
      setPreview(null)
      return
    }
    const seq = ++previewSeq.current
    const timer = setTimeout(() => {
      previewInvitation({ email: trimmed, role_ids: roleIds, group_ids: groupIds })
        .then((p) => {
          if (seq === previewSeq.current) setPreview(p)
        })
        .catch(() => {
          if (seq === previewSeq.current) setPreview(null)
        })
    }, 350)
    return () => clearTimeout(timer)
  }, [open, trimmed, emailLooksValid, roleIds, groupIds])

  const codeMessage = (code: string | undefined) =>
    code && KNOWN_CODES.has(code) ? t(`org.invite.code.${code}`) : t('org.invite.code.generic')

  const close = () => {
    onOpenChange(false)
    setEmail('')
    setRoleIds([])
    setGroupIds([])
    setSeeded(false)
    setAccessEnds('')
    setError(null)
    setPreview(null)
    setLink(null)
    setCopied(false)
  }

  const outside = Boolean(preview?.outside)
  const endRequired = Boolean(preview?.access_end_required)
  const refused = preview ? !preview.allowed : false

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!tenantSlug) return
    if (roleIds.length === 0) {
      setError(t('org.invite.chooseRole'))
      return
    }
    setBusy(true)
    setError(null)
    try {
      const invitation = await createTenantInvitation(tenantSlug, {
        email: trimmed,
        role_ids: roleIds,
        group_ids: groupIds.length > 0 ? groupIds : undefined,
        access_expires_at: outside && accessEnds ? endOfDayISO(accessEnds) : undefined,
      })
      const who = invitation.email || trimmed
      setLink({
        email: who,
        url: invitation.token ? buildInvitationLink(invitation.token) : null,
        lookalikeOf: invitation.lookalike_of,
        accessExpiresAt: invitation.access_expires_at,
        outside: invitation.member_kind === 'external' || outside,
        mfaRequired: Boolean(invitation.privileged),
      })
      toast.success(t('org.invite.created', undefined, { email: who }))
      onInvited?.()
    } catch (err) {
      setError(codeMessage(err instanceof ApiClientError ? err.code : undefined))
    } finally {
      setBusy(false)
    }
  }

  const formatDate = (iso: string) =>
    new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : close())}>
      <DialogContent size="md">
        {link ? (
          <>
            <DialogHeader>
              <DialogTitle>{t('org.invite.createdTitle')}</DialogTitle>
              <DialogDescription>
                {t('org.invite.createdBody', undefined, { email: link.email })}
              </DialogDescription>
            </DialogHeader>
            <DialogBody className="grid gap-4">
              {link.lookalikeOf && link.lookalikeOf.length > 0 && (
                <Alert className="border-warning/40 bg-warning/10" data-testid="invite-lookalike">
                  <ShieldAlert className="size-4 text-warning" />
                  <AlertTitle>{t('org.invite.lookalikeTitle')}</AlertTitle>
                  <AlertDescription>
                    {t('org.invite.lookalikeBody', undefined, {
                      email: link.email,
                      others: link.lookalikeOf.join(', '),
                    })}
                  </AlertDescription>
                </Alert>
              )}
              {link.outside && (
                <div
                  className="space-y-1 text-sm text-muted-foreground"
                  data-testid="invite-outside-note"
                >
                  <p>{t('org.invite.outsideJoined', undefined, { email: link.email })}</p>
                  {link.mfaRequired && <p>{t('org.invite.mfaNote')}</p>}
                  {link.accessExpiresAt && (
                    <p data-testid="invite-access-ends">
                      {t('org.invite.accessEndsOn', undefined, {
                        date: formatDate(link.accessExpiresAt),
                      })}
                    </p>
                  )}
                </div>
              )}
              {link.url ? (
                <div className="space-y-3 py-2">
                  <div className="space-y-1.5">
                    <p className="text-sm font-medium">{t('org.invite.link')}</p>
                    <div className="flex min-w-0 items-center gap-2">
                      <code
                        className="min-w-0 flex-1 rounded bg-muted px-2 py-1.5 font-mono text-xs break-all select-all"
                        data-testid="invitation-link"
                      >
                        {link.url}
                      </code>
                      <Button
                        type="button"
                        size="icon"
                        variant="outline"
                        aria-label={t('org.invite.copyLink')}
                        onClick={async () => {
                          if (link.url && (await copyToClipboard(link.url))) setCopied(true)
                        }}
                      >
                        {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                      </Button>
                    </div>
                  </div>
                  <Alert className="border-warning/40 bg-warning/10">
                    <ShieldAlert className="size-4 text-warning" />
                    <AlertTitle>{t('org.invite.shownOnceTitle')}</AlertTitle>
                    <AlertDescription>
                      {t('org.invite.shownOnceBody', undefined, { email: link.email })}
                    </AlertDescription>
                  </Alert>
                </div>
              ) : (
                <Alert className="my-2">
                  <Mail className="size-4" />
                  <AlertTitle>{t('org.invite.emailedTitle')}</AlertTitle>
                  <AlertDescription>
                    {t('org.invite.emailedBody', undefined, { email: link.email })}
                  </AlertDescription>
                </Alert>
              )}
            </DialogBody>
            <DialogFooter>
              <Button onClick={close}>{t('org.invite.done')}</Button>
            </DialogFooter>
          </>
        ) : (
          <DialogForm onSubmit={submit}>
            <DialogHeader>
              <DialogTitle>{t('org.invite.title')}</DialogTitle>
              <DialogDescription>{t('org.invite.description')}</DialogDescription>
            </DialogHeader>

            <DialogBody>
              <div className="space-y-6 py-2">
                <div className="space-y-2">
                  <Label htmlFor="invite-email">{t('org.invite.email')}</Label>
                  <div className="relative">
                    <Mail
                      className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
                      aria-hidden="true"
                    />
                    <Input
                      id="invite-email"
                      type="email"
                      required
                      autoComplete="off"
                      placeholder={t('org.invite.emailPlaceholder')}
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="h-11 ps-10"
                      disabled={busy}
                      aria-invalid={refused || undefined}
                      aria-describedby="invite-email-note"
                    />
                  </div>
                  <div id="invite-email-note" aria-live="polite">
                    {refused && (
                      <p className="text-sm text-destructive" data-testid="invite-refusal">
                        {codeMessage(preview?.reason)}
                      </p>
                    )}
                  </div>
                </div>

                {preview?.allowed && outside && (
                  <Alert data-testid="invite-outside">
                    <Info className="size-4" />
                    <AlertTitle>
                      {preview.personal
                        ? t('org.invite.personalTitle')
                        : t('org.invite.outsideTitle')}
                    </AlertTitle>
                    <AlertDescription>
                      <ul className="list-disc space-y-1 ps-4">
                        <li>{t('org.invite.outsideBadge')}</li>
                        {preview.step_up_required && <li>{t('org.invite.stepUpNote')}</li>}
                        {preview.mfa_required && <li>{t('org.invite.mfaNote')}</li>}
                        {preview.sso_exception_needed && (
                          <li>{t('org.invite.ssoExceptionNote')}</li>
                        )}
                      </ul>
                    </AlertDescription>
                  </Alert>
                )}

                <div className="space-y-3">
                  <div>
                    <Label id="invite-roles-label">{t('org.invite.role')}</Label>
                    <p className="text-xs text-muted-foreground">{t('org.invite.roleHint')}</p>
                  </div>
                  <RolePicker
                    canGrantAdmin={canGrantAdmin}
                    roles={roles}
                    selected={roleIds}
                    onChange={setRoleIds}
                    loading={rolesLoading}
                    disabled={busy}
                  />
                </div>

                <div className="space-y-3">
                  <div>
                    <Label id="invite-teams-label">{t('org.invite.teams.label')}</Label>
                    <p className="text-xs text-muted-foreground">{t('org.invite.teams.hint')}</p>
                  </div>
                  <TeamPicker
                    teams={teams}
                    selected={groupIds}
                    onChange={setGroupIds}
                    loading={teamsLoading}
                    disabled={busy}
                    labelledBy="invite-teams-label"
                  />
                </div>

                {outside && (
                  <div className="space-y-2">
                    <Label htmlFor="invite-access-ends">
                      {endRequired
                        ? t('org.invite.accessEndsRequired')
                        : t('org.invite.accessEndsOptional')}
                    </Label>
                    <Input
                      id="invite-access-ends"
                      type="date"
                      min={dateInputDaysFromNow(1)}
                      max={dateInputDaysFromNow(preview?.max_access_end_days ?? 365)}
                      value={accessEnds}
                      onChange={(e) => setAccessEnds(e.target.value)}
                      disabled={busy}
                      aria-describedby="invite-access-ends-hint"
                    />
                    <p id="invite-access-ends-hint" className="text-xs text-muted-foreground">
                      {endRequired
                        ? t('org.invite.accessEndsRequiredHint', undefined, {
                            days: preview?.default_access_end_days ?? 90,
                          })
                        : t('org.invite.accessEndsOptionalHint')}
                    </p>
                  </div>
                )}

                {error && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}
              </div>
            </DialogBody>

            <DialogFooter>
              <Button type="button" variant="ghost" onClick={close}>
                {t('org.invite.cancel')}
              </Button>
              <Button type="submit" disabled={busy || !tenantSlug || !trimmed || refused}>
                {busy ? (
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                ) : (
                  <Send className="me-2 h-4 w-4" />
                )}
                {t('org.invite.send')}
              </Button>
            </DialogFooter>
          </DialogForm>
        )}
      </DialogContent>
    </Dialog>
  )
}
