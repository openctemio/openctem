'use client'

/**
 * Trusted organizations (api RFC-058).
 *
 * A host organization trusts the organization that manages a partner's
 * email domain (its "home"). Once the home's owner approves, people from
 * the home can be invited as members at most (never admin or owner), sign
 * in here with their own company's SSO, and lose access here when they
 * leave the home. Two lists: organizations we trust (outgoing) and
 * organizations that trust us (incoming, where our people work).
 */

import { useState, type FormEvent } from 'react'
import { AlertCircle, Building2, Check, Loader2, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
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
import { Switch } from '@/components/ui/switch'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  approveOrgTrust,
  createOrgTrust,
  deleteOrgTrust,
  updateOrgTrust,
  useOrgTrusts,
  type OrgTrust,
  type OrgTrustMaxRole,
  type OrgTrustSettingsInput,
} from '../api/use-org-trusts'
import { MAX_EXTERNAL_ACCESS_DAYS, formatShortDate } from '../lib/external-access'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { PageStack } from '@/features/shared'

const DEFAULT_SETTINGS: OrgTrustSettingsInput = {
  max_role: 'member',
  accept_home_sso: true,
  require_mfa_evidence: false,
  allow_api_keys: false,
}

function settingsOf(t: OrgTrust): OrgTrustSettingsInput {
  return {
    max_role: t.max_role,
    accept_home_sso: t.accept_home_sso,
    require_mfa_evidence: t.require_mfa_evidence,
    allow_api_keys: t.allow_api_keys,
    default_expiry_days: t.default_expiry_days,
  }
}

function StatusBadge({ trust }: { trust: OrgTrust }) {
  const { t } = useTranslation()
  if (trust.status === 'active') {
    return (
      <Badge variant="outline" className="border-success/40 text-success">
        {t('settings.trust.status.active', 'Active')}
      </Badge>
    )
  }
  return (
    <Badge variant="outline" className="border-warning/40 text-warning">
      {trust.direction === 'outgoing'
        ? t('settings.trust.status.waitingTheirs', 'Waiting for their owner')
        : t('settings.trust.status.waitingYours', 'Waiting for your approval')}
    </Badge>
  )
}

/** The settings a host chooses for a trust (create and edit share it). */
function TrustSettingsFields({
  value,
  onChange,
  disabled,
}: {
  value: OrgTrustSettingsInput
  onChange: (v: OrgTrustSettingsInput) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  return (
    <PageStack>
      <div className="space-y-2">
        <Label htmlFor="trust-max-role">{t('settings.trust.maxRole', 'Highest role')}</Label>
        <Select
          value={value.max_role}
          onValueChange={(v) => onChange({ ...value, max_role: v as OrgTrustMaxRole })}
          disabled={disabled}
        >
          <SelectTrigger id="trust-max-role" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="viewer">{t('settings.trust.role.viewerTitle', 'Viewer')}</SelectItem>
            <SelectItem value="member">{t('settings.trust.role.memberTitle', 'Member')}</SelectItem>
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          {t(
            'settings.trust.maxRoleHint',
            'People from a partner never become admin or owner here. They join as viewers with no data until you add them to a team.'
          )}
        </p>
      </div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <Label htmlFor="trust-home-sso">
            {t('settings.trust.homeSso', "Accept their company's SSO")}
          </Label>
          <p className="text-xs text-muted-foreground">
            {t(
              'settings.trust.homeSsoHint',
              'A sign-in at their identity provider counts as SSO here.'
            )}
          </p>
        </div>
        <Switch
          id="trust-home-sso"
          checked={value.accept_home_sso}
          onCheckedChange={(c) => onChange({ ...value, accept_home_sso: c })}
          disabled={disabled}
        />
      </div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <Label htmlFor="trust-mfa-evidence">
            {t('settings.trust.mfaEvidence', 'Require proof of MFA')}
          </Label>
          <p className="text-xs text-muted-foreground">
            {t(
              'settings.trust.mfaEvidenceHint',
              'Accept their SSO only when their identity provider reports a second factor.'
            )}
          </p>
        </div>
        <Switch
          id="trust-mfa-evidence"
          checked={value.require_mfa_evidence}
          onCheckedChange={(c) => onChange({ ...value, require_mfa_evidence: c })}
          disabled={disabled}
        />
      </div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <Label htmlFor="trust-api-keys">
            {t('settings.trust.allowApiKeys', 'Allow API keys')}
          </Label>
          <p className="text-xs text-muted-foreground">
            {t(
              'settings.trust.allowApiKeysHint',
              'Their people may create API keys in this organization.'
            )}
          </p>
        </div>
        <Switch
          id="trust-api-keys"
          checked={value.allow_api_keys}
          onCheckedChange={(c) => onChange({ ...value, allow_api_keys: c })}
          disabled={disabled}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="trust-expiry">
          {t('settings.trust.expiry', 'Proposed end of access (days, optional)')}
        </Label>
        <Input
          id="trust-expiry"
          type="number"
          min={1}
          max={MAX_EXTERNAL_ACCESS_DAYS}
          value={value.default_expiry_days ?? ''}
          onChange={(e) =>
            onChange({
              ...value,
              default_expiry_days: e.target.value ? Number(e.target.value) : undefined,
            })
          }
          disabled={disabled}
        />
      </div>
    </PageStack>
  )
}

function CreateTrustDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: () => void
}) {
  const { t } = useTranslation()
  const [domain, setDomain] = useState('')
  const [settings, setSettings] = useState<OrgTrustSettingsInput>(DEFAULT_SETTINGS)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const close = () => {
    onOpenChange(false)
    setDomain('')
    setSettings(DEFAULT_SETTINGS)
    setError(null)
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await createOrgTrust({ home_domain: domain.trim().toLowerCase(), ...settings })
      toast.success(t('settings.trust.requested', 'Trust requested. Their owner must approve it.'))
      onCreated()
      close()
    } catch (err) {
      setError(
        getErrorMessage(err, t('settings.trust.requestFailed', 'Could not request the trust'))
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : close())}>
      <DialogContent>
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t('settings.trust.create.title', 'Trust an organization')}</DialogTitle>
            <DialogDescription>
              {t(
                'settings.trust.create.description',
                'Enter an email domain the partner organization verified for SSO. Their owner approves the trust before it applies.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-5 py-4">
              <div className="space-y-2">
                <Label htmlFor="trust-domain">
                  {t('settings.trust.create.domain', 'Their email domain')}
                </Label>
                <Input
                  id="trust-domain"
                  required
                  placeholder={t('settings.trust.create.domainPlaceholder', 'partner.com')}
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  disabled={busy}
                />
              </div>
              <TrustSettingsFields value={settings} onChange={setSettings} disabled={busy} />
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
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={busy || !domain.trim()}>
              {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              {t('settings.trust.create.submit', 'Request trust')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

function EditTrustDialog({
  trust,
  onOpenChange,
  onSaved,
}: {
  trust: OrgTrust | null
  onOpenChange: (open: boolean) => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const [settings, setSettings] = useState<OrgTrustSettingsInput>(DEFAULT_SETTINGS)
  const [busy, setBusy] = useState(false)
  const [loadedFor, setLoadedFor] = useState<string | null>(null)
  if (trust && loadedFor !== trust.id) {
    setLoadedFor(trust.id)
    setSettings(settingsOf(trust))
  }

  const save = async () => {
    if (!trust) return
    setBusy(true)
    try {
      await updateOrgTrust(trust.id, settings)
      toast.success(t('settings.trust.updated', 'Trust updated'))
      onSaved()
      onOpenChange(false)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('settings.trust.updateFailed', 'Could not update the trust'))
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open={!!trust}
      onOpenChange={(next) => {
        if (!next) setLoadedFor(null)
        onOpenChange(next)
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {t('settings.trust.edit.title', 'Trust settings: {org}', {
              org: trust?.organization ?? '',
            })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'settings.trust.edit.description',
              'Changes apply to new sign-ins and invitations of people from this organization.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="py-4">
            <TrustSettingsFields value={settings} onChange={setSettings} disabled={busy} />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={save} disabled={busy}>
            {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('common.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function ApproveTrustDialog({
  trust,
  onOpenChange,
  onApproved,
}: {
  trust: OrgTrust | null
  onOpenChange: (open: boolean) => void
  onApproved: () => void
}) {
  const { t } = useTranslation()
  const [attest, setAttest] = useState(false)
  const [busy, setBusy] = useState(false)

  const approve = async () => {
    if (!trust) return
    setBusy(true)
    try {
      await approveOrgTrust(trust.id, attest)
      toast.success(
        t('settings.trust.approved', '{org} now trusts your organization', {
          org: trust.organization,
        })
      )
      onApproved()
      onOpenChange(false)
      setAttest(false)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('settings.trust.approveFailed', 'Could not approve the trust'))
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={!!trust} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>
            {t('settings.trust.approve.title', 'Approve trust from {org}', {
              org: trust?.organization ?? '',
            })}
          </DialogTitle>
          <DialogDescription>
            {trust?.max_role === 'viewer'
              ? t(
                  'settings.trust.approve.descriptionViewer',
                  "Your people can then be invited to {org} as viewers and sign in there with this organization's SSO. When someone leaves your organization, their access there ends too.",
                  { org: trust?.organization ?? '' }
                )
              : t(
                  'settings.trust.approve.descriptionMember',
                  "Your people can then be invited to {org} as members at most and sign in there with this organization's SSO. When someone leaves your organization, their access there ends too.",
                  { org: trust?.organization ?? '' }
                )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="flex items-start gap-3 py-4">
            <Checkbox
              id="trust-attest-mfa"
              checked={attest}
              onCheckedChange={(c) => setAttest(c === true)}
              disabled={busy}
            />
            <Label htmlFor="trust-attest-mfa" className="text-sm leading-snug font-normal">
              {t(
                'settings.trust.approve.attest',
                'Our identity provider requires a second factor for everyone.'
              )}
            </Label>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={approve} disabled={busy}>
            {busy ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <Check className="me-2 h-4 w-4" />
            )}
            {t('settings.trust.approve.submit', 'Approve')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function TrustRow({
  trust,
  canChange,
  onEdit,
  onApprove,
  onEnd,
}: {
  trust: OrgTrust
  canChange: boolean
  onEdit: (t: OrgTrust) => void
  onApprove: (t: OrgTrust) => void
  onEnd: (t: OrgTrust) => void
}) {
  const { t } = useTranslation()
  const facts = [
    trust.max_role === 'viewer'
      ? t('settings.trust.fact.upToViewer', 'Up to viewer')
      : t('settings.trust.fact.upToMember', 'Up to member'),
    trust.accept_home_sso
      ? t('settings.trust.fact.ssoAccepted', 'their SSO accepted')
      : t('settings.trust.fact.ssoNotAccepted', 'their SSO not accepted'),
    trust.require_mfa_evidence ? t('settings.trust.fact.mfaRequired', 'MFA proof required') : null,
    trust.home_attests_mfa ? t('settings.trust.fact.mfaAttested', 'MFA attested') : null,
    trust.allow_api_keys ? t('settings.trust.fact.apiKeys', 'API keys allowed') : null,
  ].filter(Boolean)
  return (
    <li
      className="flex flex-col gap-3 py-3 sm:flex-row sm:items-center"
      data-testid="org-trust-row"
    >
      <div className="flex min-w-0 flex-1 items-start gap-3">
        <Building2 className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <p className="truncate font-medium">{trust.organization}</p>
            <StatusBadge trust={trust} />
          </div>
          <p className="text-xs text-muted-foreground">
            {facts.join(' · ')}
            {trust.accepted_at
              ? ` · ${t('settings.trust.fact.since', 'since {date}', {
                  date: formatShortDate(trust.accepted_at),
                })}`
              : ''}
          </p>
        </div>
      </div>
      {canChange && (
        <div className="flex shrink-0 gap-2">
          {trust.direction === 'incoming' && trust.status === 'requested' && (
            <Button size="sm" onClick={() => onApprove(trust)}>
              {t('settings.trust.approve.submit', 'Approve')}
            </Button>
          )}
          {trust.direction === 'outgoing' && (
            <Button size="sm" variant="outline" onClick={() => onEdit(trust)}>
              {t('settings.trust.settings', 'Settings')}
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            className="text-destructive"
            onClick={() => onEnd(trust)}
            aria-label={t('settings.trust.endLabel', 'End trust with {org}', {
              org: trust.organization,
            })}
          >
            <Trash2 className="size-4" />
          </Button>
        </div>
      )}
    </li>
  )
}

/** Settings › Trusted organizations. Owners change trusts; admins read them. */
export function TrustedOrganizations({ canRead, isOwner }: { canRead: boolean; isOwner: boolean }) {
  const { t } = useTranslation()
  const { trusts, isLoading, error, mutate } = useOrgTrusts(canRead)
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<OrgTrust | null>(null)
  const [approving, setApproving] = useState<OrgTrust | null>(null)
  const [ending, setEnding] = useState<OrgTrust | null>(null)
  const [endBusy, setEndBusy] = useState(false)

  const outgoing = trusts.filter((t) => t.direction === 'outgoing')
  const incoming = trusts.filter((t) => t.direction === 'incoming')
  const refresh = () => void mutate()

  const end = async () => {
    if (!ending) return
    setEndBusy(true)
    try {
      await deleteOrgTrust(ending.id)
      toast.success(
        t('settings.trust.ended', 'Trust with {org} ended', { org: ending.organization })
      )
      setEnding(null)
      refresh()
    } catch (err) {
      toast.error(getErrorMessage(err, t('settings.trust.endFailed', 'Could not end the trust')))
    } finally {
      setEndBusy(false)
    }
  }

  if (!canRead) {
    return (
      <Alert>
        <AlertDescription>
          {t('settings.trust.readDenied', 'Only owners and admins can see trusted organizations.')}
        </AlertDescription>
      </Alert>
    )
  }

  const list = (items: OrgTrust[], empty: string) =>
    isLoading ? (
      <div className="space-y-2">
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
      </div>
    ) : items.length === 0 ? (
      <p className="py-3 text-sm text-muted-foreground">{empty}</p>
    ) : (
      <ul className="divide-y">
        {items.map((t) => (
          <TrustRow
            key={t.id}
            trust={t}
            canChange={isOwner}
            onEdit={setEditing}
            onApprove={setApproving}
            onEnd={setEnding}
          />
        ))}
      </ul>
    )

  return (
    <div className="space-y-5">
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {getErrorMessage(
              error,
              t('settings.trust.loadFailed', 'Could not load trusted organizations')
            )}
          </AlertDescription>
        </Alert>
      )}
      {!isOwner && (
        <Alert>
          <AlertDescription>
            {t('settings.trust.ownerOnly', 'Only an owner can request, approve or end a trust.')}
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
          <div>
            <CardTitle className="text-base">
              {t('settings.trust.outgoing.title', 'Organizations you trust')}
            </CardTitle>
            <CardDescription>
              {t(
                'settings.trust.outgoing.description',
                "People from these organizations can be invited here and sign in with their own company's SSO."
              )}
            </CardDescription>
          </div>
          {isOwner && (
            <Button size="sm" onClick={() => setCreateOpen(true)} className="shrink-0">
              <Plus className="me-2 size-4" />
              {t('settings.trust.create.title', 'Trust an organization')}
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {list(outgoing, t('settings.trust.outgoing.empty', 'You trust no organization yet.'))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('settings.trust.incoming.title', 'Organizations that trust you')}
          </CardTitle>
          <CardDescription>
            {t(
              'settings.trust.incoming.description',
              'Your people work in these organizations. When someone leaves your organization, their access there ends too.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {list(incoming, t('settings.trust.incoming.empty', 'No organization trusts yours.'))}
        </CardContent>
      </Card>

      <CreateTrustDialog open={createOpen} onOpenChange={setCreateOpen} onCreated={refresh} />
      <EditTrustDialog
        trust={editing}
        onOpenChange={(o) => !o && setEditing(null)}
        onSaved={refresh}
      />
      <ApproveTrustDialog
        trust={approving}
        onOpenChange={(o) => !o && setApproving(null)}
        onApproved={refresh}
      />
      <ConfirmDialog
        open={!!ending}
        onOpenChange={(o) => !o && !endBusy && setEnding(null)}
        destructive
        title={t('confirm.orgTrust.endTitle', 'End trust with {org}?', {
          org: ending?.organization ?? '',
        })}
        desc={
          ending?.direction === 'outgoing'
            ? t(
                'confirm.orgTrust.endOutgoingDesc',
                'Members from {org} are disabled here at once. Nothing is deleted: an owner can enable them again.',
                { org: ending?.organization ?? '' }
              )
            : t(
                'confirm.orgTrust.endIncomingDesc',
                'Your people are disabled in {org} at once. Nothing is deleted.',
                { org: ending?.organization ?? '' }
              )
        }
        confirmText={
          <>
            {endBusy && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('confirm.orgTrust.end', 'End trust')}
          </>
        }
        isLoading={endBusy}
        handleConfirm={() => end()}
      />
    </div>
  )
}
