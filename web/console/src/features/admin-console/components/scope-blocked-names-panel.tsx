'use client'

/**
 * Scanning > Platform scanning > Blocked names (RFC-154): the government and
 * military rule of the scope guardrails, the operator's own blocked names, and
 * the organizations' exceptions. Any administrator reads them; a platform
 * owner changes them with a reason and an authenticator code (on a hosted
 * service a second owner approves grants, extensions and turning the rule
 * off, through the console's approval prompt). Loopback, link-local and cloud
 * metadata addresses, public suffixes, shared provider apexes and the range
 * caps are not part of this page and never change.
 */

import { useEffect, useId, useMemo, useState, type ReactNode } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { AlertTriangle, Loader2, Lock } from 'lucide-react'
import { toast } from 'sonner'
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
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable, ErrorState, PageStack } from '@/features/shared'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { useSearchQuery } from '@/hooks/use-search-query'
import { AdminApiError } from '@console/lib/admin-api/client'
import { useOrganizations } from '../api/use-admin-organizations'
import {
  extendScopeNameException,
  grantScopeNameException,
  revokeScopeNameException,
  saveScopeBlockedNames,
  useScopeBlockedNames,
  useScopeNameExceptions,
  type ScopeBlockedNames,
  type ScopeNameException,
} from '../api/use-scope-blocked-names'
import { SettingChangedLine } from './console-setting-parts'
import { RoleRequiredNotice } from './role-required-notice'
import { StepUpCodeField, stepUpCodeReady, useStepUpCodeOptional } from './step-up-code-hint'

/** The platform permission every change on this page needs. */
export const SCOPE_GUARDRAILS_PERMISSION = 'platform.settings.scope_guardrails'

const DAY_MS = 24 * 60 * 60 * 1000

/** YYYY-MM-DD of a date, UTC. */
function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10)
}

function shortDate(iso: string): string {
  return iso.slice(0, 10)
}

/** The names typed one per line (or comma separated), trimmed, without blanks. */
export function parseNames(text: string): string[] {
  return text
    .split(/[\n,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s !== '')
}

function errorText(e: unknown, fallback: string): string {
  return e instanceof AdminApiError || e instanceof Error ? e.message : fallback
}

/**
 * A guarded dialog: its fields, the reason and the authenticator code; the
 * submit error shows in the footer, next to the buttons.
 */
function GuardedDialog({
  open,
  onOpenChange,
  title,
  desc,
  children,
  confirmText,
  destructive,
  ready,
  onConfirm,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  desc: string
  children?: ReactNode
  confirmText: string
  destructive?: boolean
  ready: boolean
  onConfirm: (reason: string, code: string) => Promise<void>
}) {
  const { t } = useTranslation()
  const id = useId()
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const codeOptional = useStepUpCodeOptional()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [codeError, setCodeError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) {
      setReason('')
      setCode('')
      setError(null)
      setCodeError(null)
    }
  }, [open])

  const submit = async () => {
    setBusy(true)
    setError(null)
    setCodeError(null)
    try {
      await onConfirm(reason.trim(), code.trim())
      onOpenChange(false)
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
      } else {
        setError(errorText(e, t('admin.blockedNames.saveFailed', 'Could not save the change')))
      }
    } finally {
      setBusy(false)
    }
  }

  const canSubmit =
    ready && reason.trim() !== '' && reason.length <= 500 && stepUpCodeReady(code, codeOptional)

  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{desc}</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-4">
            {children}
            <div className="space-y-2">
              <Label htmlFor={`${id}-reason`}>{t('admin.settings.reason', 'Reason')}</Label>
              <Textarea
                id={`${id}-reason`}
                rows={2}
                maxLength={500}
                value={reason}
                onChange={(e) => setReason(e.target.value.replace(/[\r\n]+/g, ' '))}
                placeholder={t(
                  'admin.settings.reasonPlaceholder',
                  'Why this change? Recorded in the admin audit log and sent to every administrator.'
                )}
              />
            </div>
            <StepUpCodeField
              id={`${id}-code`}
              value={code}
              onChange={setCode}
              optional={codeOptional}
              error={codeError}
            />
          </div>
        </DialogBody>
        <DialogFooter className="flex-wrap items-center">
          {error && (
            <p role="alert" className="me-auto basis-full text-sm text-destructive sm:basis-auto">
              {error}
            </p>
          )}
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('confirm.cancel', 'Cancel')}
          </Button>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            onClick={() => void submit()}
            disabled={!canSubmit || busy}
          >
            {busy && <Loader2 className="me-1.5 size-4 animate-spin" aria-hidden />}
            {confirmText}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The rule switch, the operator's names and the longest exception. */
function PolicyCard({
  data,
  canEdit,
  onSaved,
}: {
  data: ScopeBlockedNames
  canEdit: boolean
  onSaved: () => Promise<unknown>
}) {
  const { t } = useTranslation()
  const id = useId()
  const [rule, setRule] = useState(data.government_rule)
  const [names, setNames] = useState(data.names.join('\n'))
  const [maxDays, setMaxDays] = useState(String(data.max_exception_days))
  const [open, setOpen] = useState(false)

  useEffect(() => {
    setRule(data.government_rule)
    setNames(data.names.join('\n'))
    setMaxDays(String(data.max_exception_days))
  }, [data])

  const parsedDays = Number.parseInt(maxDays, 10)
  const daysOk = Number.isInteger(parsedDays) && parsedDays >= 1 && parsedDays <= 1095
  const dirty =
    rule !== data.government_rule ||
    parseNames(names).join('\n') !== data.names.join('\n') ||
    parsedDays !== data.max_exception_days
  const reset = () => {
    setRule(data.government_rule)
    setNames(data.names.join('\n'))
    setMaxDays(String(data.max_exception_days))
  }
  const turningOff = data.government_rule && !rule

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('admin.blockedNames.title', 'Blocked target names')}</CardTitle>
        <CardDescription>
          {t(
            'admin.blockedNames.desc',
            'Names no organization may add to its scope or scan. Checked when an entry is added and again before every scan.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {!data.government_rule && (
          <Alert variant="destructive" data-testid="government-rule-off-warning">
            <AlertTriangle className="size-4" aria-hidden />
            <AlertTitle>
              {t(
                'admin.blockedNames.offWarningTitle',
                'Government and military names are not blocked'
              )}
            </AlertTitle>
            <AlertDescription>
              {t(
                'admin.blockedNames.offWarning',
                'Any organization on this installation may add a government or military domain to its scope. Turn the rule back on unless this installation serves only authorised testing of such domains.'
              )}
            </AlertDescription>
          </Alert>
        )}
        <div className="flex items-start justify-between gap-4">
          <Label htmlFor={`${id}-rule`} className="grid min-w-0 gap-1 font-normal">
            <span className="font-medium">
              {t('admin.blockedNames.ruleLabel', 'Block government and military names')}
            </span>
            <span className="text-sm text-muted-foreground">
              {t(
                'admin.blockedNames.ruleHint',
                'Names such as *.gov, *.mil, gov.xx, mil.xx and gouv, gob, go or govt under a country code. On by default. Grant an exception below for one organization and one name instead of turning it off.'
              )}
            </span>
          </Label>
          <Switch id={`${id}-rule`} checked={rule} onCheckedChange={setRule} disabled={!canEdit} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-names`}>
            {t('admin.blockedNames.namesLabel', 'Also blocked on this installation')}
          </Label>
          <Textarea
            id={`${id}-names`}
            rows={3}
            value={names}
            onChange={(e) => setNames(e.target.value)}
            disabled={!canEdit}
            spellCheck={false}
            placeholder="internal.example.com"
          />
          <p className="text-xs text-muted-foreground">
            {t(
              'admin.blockedNames.namesHint',
              'One domain per line; the names under it are blocked too. Exceptions never lift these names.'
            )}
          </p>
          {data.env_names.length > 0 && (
            <p className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
              <Lock className="size-3" aria-hidden />
              {t('admin.blockedNames.envNames', 'Set on the server (SCOPE_DENY_EXTRA):')}
              {data.env_names.map((n) => (
                <Badge key={n} variant="outline" className="font-mono">
                  {n}
                </Badge>
              ))}
            </p>
          )}
        </div>
        <div className="grid max-w-xs gap-1.5">
          <Label htmlFor={`${id}-days`}>
            {t('admin.blockedNames.maxDaysLabel', 'Longest exception (days)')}
          </Label>
          <Input
            id={`${id}-days`}
            type="number"
            inputMode="numeric"
            min={1}
            max={1095}
            value={maxDays}
            onChange={(e) => setMaxDays(e.target.value)}
            disabled={!canEdit}
          />
        </div>
        <p className="text-sm text-muted-foreground">
          {t(
            'admin.blockedNames.alwaysOn',
            'Always blocked, whatever this page says: loopback, link-local and cloud metadata addresses, the whole address space, public suffixes, shared provider domains as wildcard roots, and ranges larger than the server allows.'
          )}
        </p>
        <SettingChangedLine change={data} />
        {canEdit ? (
          <SettingsSaveBar
            className="basis-full"
            dirty={dirty}
            saving={false}
            saveDisabled={!daysOk}
            onSave={() => setOpen(true)}
            onDiscard={reset}
          />
        ) : (
          <RoleRequiredNotice permission={SCOPE_GUARDRAILS_PERMISSION} />
        )}
      </CardContent>
      <GuardedDialog
        open={open}
        onOpenChange={setOpen}
        title={
          turningOff
            ? t(
                'admin.blockedNames.confirmOffTitle',
                'Stop blocking government and military names?'
              )
            : t('admin.blockedNames.confirmTitle', 'Save the blocked names')
        }
        desc={
          turningOff
            ? data.second_approval
              ? t(
                  'admin.blockedNames.confirmOffDescApproval',
                  'Every organization may then add such names to its scope. Another platform owner must approve this change first.'
                )
              : t(
                  'admin.blockedNames.confirmOffDesc',
                  'Every organization may then add such names to its scope. The change is recorded in the admin audit log and every administrator is told.'
                )
            : t(
                'admin.blockedNames.confirmDesc',
                'The change applies at once. It is recorded in the admin audit log and every administrator is told.'
              )
        }
        confirmText={
          turningOff
            ? t('admin.blockedNames.turnOff', 'Turn the rule off')
            : t('admin.blockedNames.save', 'Save')
        }
        destructive={turningOff}
        ready={daysOk}
        onConfirm={async (reason, code) => {
          await saveScopeBlockedNames(
            {
              government_rule: rule,
              names: parseNames(names),
              max_exception_days: parsedDays,
              version: data.version,
              reason,
            },
            code
          )
          await onSaved()
          toast.success(t('admin.blockedNames.saved', 'Blocked names saved'))
        }}
      />
    </Card>
  )
}

function OrganizationField({
  value,
  onChange,
}: {
  value: { id: string; name: string } | null
  onChange: (v: { id: string; name: string } | null) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const [input, setInput] = useState('')
  const { term } = useSearchQuery(input)
  const { data } = useOrganizations({ search: term, perPage: 8 })
  if (value) {
    return (
      <div className="grid gap-1.5">
        <Label>{t('admin.blockedNames.organization', 'Organization')}</Label>
        <div className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm">
          <span className="truncate font-medium">{value.name}</span>
          <Button variant="ghost" size="sm" onClick={() => onChange(null)}>
            {t('admin.blockedNames.change', 'Change')}
          </Button>
        </div>
      </div>
    )
  }
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{t('admin.blockedNames.organization', 'Organization')}</Label>
      <Input
        id={id}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder={t('admin.blockedNames.organizationSearch', 'Search organizations')}
        autoComplete="off"
      />
      {term && (data?.data?.length ?? 0) > 0 && (
        <ul className="max-h-48 overflow-y-auto rounded-md border">
          {data?.data.map((o) => (
            <li key={o.id}>
              <button
                type="button"
                className="w-full px-3 py-2 text-start text-sm hover:bg-muted"
                onClick={() => onChange({ id: o.id, name: o.name })}
              >
                <span className="font-medium">{o.name}</span>{' '}
                <span className="text-muted-foreground">{o.slug}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function GrantDialog({
  open,
  onOpenChange,
  maxDays,
  secondApproval,
  onDone,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  maxDays: number
  secondApproval: boolean
  onDone: () => Promise<unknown>
}) {
  const { t } = useTranslation()
  const id = useId()
  const [org, setOrg] = useState<{ id: string; name: string } | null>(null)
  const [name, setName] = useState('')
  const [subdomains, setSubdomains] = useState(false)
  const [ref, setRef] = useState('')
  const today = new Date()
  const maxDay = isoDay(new Date(today.getTime() + maxDays * DAY_MS))
  const [expires, setExpires] = useState(isoDay(new Date(today.getTime() + 90 * DAY_MS)))
  useEffect(() => {
    if (!open) {
      setOrg(null)
      setName('')
      setSubdomains(false)
      setRef('')
    }
  }, [open])
  const ready =
    !!org && name.trim() !== '' && ref.trim() !== '' && expires !== '' && expires <= maxDay
  return (
    <GuardedDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('admin.blockedNames.grantTitle', 'Grant an exception')}
      desc={
        secondApproval
          ? t(
              'admin.blockedNames.grantDescApproval',
              'Lets one organization add one government or military name to its scope until the expiry. It still needs a scope entry through every scope rule. Another platform owner must approve it first.'
            )
          : t(
              'admin.blockedNames.grantDesc',
              'Lets one organization add one government or military name to its scope until the expiry. It still needs a scope entry through every scope rule. You are responsible for checking the written authorisation.'
            )
      }
      confirmText={t('admin.blockedNames.grant', 'Grant exception')}
      ready={ready}
      onConfirm={async (reason, code) => {
        if (!org) return
        await grantScopeNameException(
          {
            organization_id: org.id,
            name: name.trim(),
            include_subdomains: subdomains,
            reason,
            authorization_ref: ref.trim(),
            expires_at: expires,
          },
          code
        )
        await onDone()
        toast.success(t('admin.blockedNames.granted', 'Exception granted'))
      }}
    >
      <OrganizationField value={org} onChange={setOrg} />
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-name`}>{t('admin.blockedNames.name', 'Domain')}</Label>
        <Input
          id={`${id}-name`}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="portal.example.gov.xx"
          spellCheck={false}
          autoComplete="off"
        />
      </div>
      <label className="flex items-start gap-2 text-sm">
        <Checkbox checked={subdomains} onCheckedChange={(v) => setSubdomains(v === true)} />
        <span>
          {t('admin.blockedNames.subdomains', 'Also the names under it')}
          <span className="block text-xs text-muted-foreground">
            {t(
              'admin.blockedNames.subdomainsHint',
              'Needed for a wildcard entry such as *.portal.example.gov.xx. Leave off to allow the exact name only.'
            )}
          </span>
        </span>
      </label>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-ref`}>
          {t('admin.blockedNames.reference', 'Written authorisation (reference)')}
        </Label>
        <Input
          id={`${id}-ref`}
          value={ref}
          maxLength={500}
          onChange={(e) => setRef(e.target.value)}
          placeholder={t(
            'admin.blockedNames.referencePlaceholder',
            'Contract, letter or program link and date'
          )}
        />
      </div>
      <div className="grid max-w-xs gap-1.5">
        <Label htmlFor={`${id}-expires`}>{t('admin.blockedNames.expires', 'Expires')}</Label>
        <Input
          id={`${id}-expires`}
          type="date"
          value={expires}
          min={isoDay(new Date(today.getTime() + DAY_MS))}
          max={maxDay}
          onChange={(e) => setExpires(e.target.value)}
        />
      </div>
    </GuardedDialog>
  )
}

function stateBadge(state: ScopeNameException['state'], t: (k: string, f: string) => string) {
  switch (state) {
    case 'active':
      return <Badge variant="secondary">{t('admin.blockedNames.state.active', 'Active')}</Badge>
    case 'expired':
      return <Badge variant="outline">{t('admin.blockedNames.state.expired', 'Expired')}</Badge>
    default:
      return <Badge variant="outline">{t('admin.blockedNames.state.revoked', 'Revoked')}</Badge>
  }
}

function ExceptionsCard({
  items,
  maxDays,
  secondApproval,
  canEdit,
  onChanged,
}: {
  items: ScopeNameException[]
  maxDays: number
  secondApproval: boolean
  canEdit: boolean
  onChanged: () => Promise<unknown>
}) {
  const { t } = useTranslation()
  const id = useId()
  const [grant, setGrant] = useState(false)
  const [extend, setExtend] = useState<ScopeNameException | null>(null)
  const [revoke, setRevoke] = useState<ScopeNameException | null>(null)
  const [newExpiry, setNewExpiry] = useState('')
  const today = new Date()
  const maxDay = isoDay(new Date(today.getTime() + maxDays * DAY_MS))
  useEffect(() => {
    if (extend) setNewExpiry(isoDay(new Date(today.getTime() + 90 * DAY_MS)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [extend])

  const columns = useMemo<ColumnDef<ScopeNameException>[]>(() => {
    const cols: ColumnDef<ScopeNameException>[] = [
      {
        accessorKey: 'organization_name',
        header: t('admin.blockedNames.organization', 'Organization'),
        cell: ({ row }) => <span className="font-medium">{row.original.organization_name}</span>,
      },
      {
        accessorKey: 'name',
        header: t('admin.blockedNames.name', 'Domain'),
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.include_subdomains ? `*.${row.original.name}` : row.original.name}
          </span>
        ),
      },
      {
        accessorKey: 'reason',
        header: t('admin.blockedNames.reasonCol', 'Reason'),
        cell: ({ row }) => (
          <span className="block max-w-56 truncate" title={row.original.reason}>
            {row.original.reason}
          </span>
        ),
      },
      {
        accessorKey: 'authorization_ref',
        header: t('admin.blockedNames.referenceCol', 'Authorisation'),
        cell: ({ row }) => (
          <span className="block max-w-48 truncate" title={row.original.authorization_ref}>
            {row.original.authorization_ref}
          </span>
        ),
      },
      {
        accessorKey: 'granted_by',
        header: t('admin.blockedNames.grantedBy', 'Granted by'),
        cell: ({ row }) => <span className="text-xs">{row.original.granted_by}</span>,
      },
      {
        accessorKey: 'expires_at',
        header: t('admin.blockedNames.expires', 'Expires'),
        cell: ({ row }) => (
          <span className="whitespace-nowrap text-xs">{shortDate(row.original.expires_at)}</span>
        ),
      },
      {
        accessorKey: 'state',
        header: t('admin.blockedNames.stateCol', 'State'),
        cell: ({ row }) => stateBadge(row.original.state, t),
      },
    ]
    if (canEdit) {
      cols.push({
        id: 'actions',
        header: () => <span className="sr-only">{t('admin.blockedNames.actions', 'Actions')}</span>,
        cell: ({ row }) =>
          row.original.state === 'revoked' ? null : (
            <div className="flex justify-end gap-1 whitespace-nowrap">
              <Button variant="ghost" size="sm" onClick={() => setExtend(row.original)}>
                {t('admin.blockedNames.extend', 'Extend')}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setRevoke(row.original)}>
                {t('admin.blockedNames.revoke', 'Revoke')}
              </Button>
            </div>
          ),
      })
    }
    return cols
  }, [canEdit, t])

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="grid gap-1.5">
          <CardTitle>{t('admin.blockedNames.exceptionsTitle', 'Exceptions')}</CardTitle>
          <CardDescription>
            {t(
              'admin.blockedNames.exceptionsDesc',
              'One organization, one name, until a date. An exception lifts only the government and military rule; organizations never see each other’s exceptions.'
            )}
          </CardDescription>
        </div>
        {canEdit && (
          <Button onClick={() => setGrant(true)}>
            {t('admin.blockedNames.grant', 'Grant exception')}
          </Button>
        )}
      </CardHeader>
      <CardContent>
        <DataTable
          columns={columns}
          data={items}
          showSearch={false}
          showColumnToggle={false}
          showPagination={items.length > 20}
          emptyMessage={t('admin.blockedNames.noExceptions', 'No exceptions.')}
        />
        {!canEdit && (
          <div className="mt-4">
            <RoleRequiredNotice permission={SCOPE_GUARDRAILS_PERMISSION} />
          </div>
        )}
      </CardContent>
      <GrantDialog
        open={grant}
        onOpenChange={setGrant}
        maxDays={maxDays}
        secondApproval={secondApproval}
        onDone={onChanged}
      />
      <GuardedDialog
        open={!!extend}
        onOpenChange={(o) => !o && setExtend(null)}
        title={t('admin.blockedNames.extendTitle', 'Extend the exception')}
        desc={
          extend
            ? t('admin.blockedNames.extendDesc', '{name} for {org}. Pick the new expiry.', {
                name: extend.name,
                org: extend.organization_name,
              })
            : ''
        }
        confirmText={t('admin.blockedNames.extend', 'Extend')}
        ready={newExpiry !== '' && newExpiry <= maxDay}
        onConfirm={async (reason, code) => {
          if (!extend) return
          await extendScopeNameException(extend.id, { expires_at: newExpiry, reason }, code)
          await onChanged()
          toast.success(t('admin.blockedNames.extended', 'Exception extended'))
        }}
      >
        <div className="grid max-w-xs gap-1.5">
          <Label htmlFor={`${id}-new-expiry`}>{t('admin.blockedNames.expires', 'Expires')}</Label>
          <Input
            id={`${id}-new-expiry`}
            type="date"
            value={newExpiry}
            min={isoDay(new Date(today.getTime() + DAY_MS))}
            max={maxDay}
            onChange={(ev) => setNewExpiry(ev.target.value)}
          />
        </div>
      </GuardedDialog>
      <GuardedDialog
        open={!!revoke}
        onOpenChange={(o) => !o && setRevoke(null)}
        title={t('admin.blockedNames.revokeTitle', 'Revoke the exception')}
        desc={
          revoke
            ? t(
                'admin.blockedNames.revokeDesc',
                '{name} for {org} is blocked again at once: its scope entries stop covering it and scans of it are refused.',
                { name: revoke.name, org: revoke.organization_name }
              )
            : ''
        }
        confirmText={t('admin.blockedNames.revoke', 'Revoke')}
        destructive
        ready
        onConfirm={async (reason, code) => {
          if (!revoke) return
          await revokeScopeNameException(revoke.id, { reason }, code)
          await onChanged()
          toast.success(t('admin.blockedNames.revoked', 'Exception revoked'))
        }}
      />
    </Card>
  )
}

/** The whole Blocked names tab. */
export function ScopeBlockedNamesPanel({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const policy = useScopeBlockedNames()
  const exceptions = useScopeNameExceptions()
  if (policy.error) {
    return (
      <ErrorState
        title={t('admin.blockedNames.errorTitle', 'Could not load the blocked names')}
        error={policy.error}
        onRetry={() => void policy.mutate()}
      />
    )
  }
  if (policy.isLoading || !policy.data) return <Skeleton className="h-72 w-full" />
  const data = policy.data
  return (
    <PageStack>
      <PolicyCard data={data} canEdit={canEdit} onSaved={() => policy.mutate()} />
      {exceptions.error ? (
        <ErrorState
          title={t('admin.blockedNames.exceptionsErrorTitle', 'Could not load the exceptions')}
          error={exceptions.error}
          onRetry={() => void exceptions.mutate()}
        />
      ) : !exceptions.data ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <ExceptionsCard
          items={exceptions.data.items}
          maxDays={data.max_exception_days}
          secondApproval={data.second_approval}
          canEdit={canEdit}
          onChanged={() => exceptions.mutate()}
        />
      )}
    </PageStack>
  )
}
