'use client'

import { useCallback, useEffect, useId, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, Loader2, Plus, Trash2 } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { AdminApiError } from '@console/lib/admin-api/client'
import { savePrivateDestinations, testPrivateDestination } from '../api/use-platform-settings'
import type {
  DestinationAddress,
  DestinationTestResult,
  PrivateDestinationsSettings,
} from '../types'
import {
  ReasonConfirmDialog,
  SettingChangedLine,
  handleSaveConflict,
} from './console-setting-parts'
import { RoleRequiredNotice } from './role-required-notice'

/** The platform permission that changes the list and runs the test. */
export const NETWORK_PERMISSION = 'platform.settings.network'

type TFn = ReturnType<typeof useTranslation>['t']

interface Row {
  key: number
  cidr: string
  note: string
}

/**
 * Whether a draft range is wider than /24 (IPv4) or /64 (IPv6): the console
 * asks for a second look. The API decides validity; this is only the hint.
 */
export function isWideDraft(cidr: string): boolean {
  const m = /^\s*([0-9a-fA-F:.]+)\/(\d{1,3})\s*$/.exec(cidr)
  if (!m) return false
  const prefix = Number(m[2])
  return m[1].includes(':') ? prefix < 64 : prefix < 24
}

/** The plain-words reason of a refused range (the API's reason code). */
export function rangeReasonText(code: string | undefined, t: TFn): string {
  switch (code) {
    case 'not_cidr':
      return t('admin.privateNetworks.reason.notCidr', 'Enter a range such as 10.20.0.0/16.')
    case 'not_private':
      return t(
        'admin.privateNetworks.reason.notPrivate',
        'Only ranges inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or fc00::/7 can be opened.'
      )
    case 'too_wide':
      return t('admin.privateNetworks.reason.tooWide', 'An IPv6 range must be /48 or narrower.')
    case 'never_reachable':
      return t(
        'admin.privateNetworks.reason.neverReachable',
        'This range holds a cloud metadata address and can never be opened.'
      )
    case 'duplicate':
      return t('admin.privateNetworks.reason.duplicate', 'This range is listed twice.')
    case 'note_too_long':
      return t('admin.privateNetworks.reason.noteTooLong', 'A note is at most 100 characters.')
    case 'note_not_plain':
      return t(
        'admin.privateNetworks.reason.noteNotPlain',
        'A note must be plain text on one line.'
      )
    case 'too_many':
      return t('admin.privateNetworks.reason.tooMany', 'At most 32 ranges can be listed.')
    default:
      return t('admin.privateNetworks.reason.invalid', 'This range is refused.')
  }
}

/** Why an address is never reachable, in plain words. */
export function hardBlockText(code: string | undefined, t: TFn): string {
  switch (code) {
    case 'loopback':
      return t('admin.privateNetworks.hard.loopback', 'the platform host itself (loopback)')
    case 'link_local':
      return t(
        'admin.privateNetworks.hard.linkLocal',
        'a link-local address, where cloud metadata services answer'
      )
    case 'cloud_metadata':
      return t('admin.privateNetworks.hard.cloudMetadata', 'a cloud metadata service')
    case 'shared_address_space':
      return t('admin.privateNetworks.hard.sharedAddress', 'carrier network address space')
    case 'multicast':
      return t('admin.privateNetworks.hard.multicast', 'a multicast address')
    case 'broadcast':
      return t('admin.privateNetworks.hard.broadcast', 'the broadcast address')
    case 'unspecified':
      return t('admin.privateNetworks.hard.unspecified', 'an unspecified address')
    case 'embedded_ipv4':
      return t(
        'admin.privateNetworks.hard.embeddedIpv4',
        'an IPv6 address that carries an IPv4 address inside'
      )
    default:
      return t('admin.privateNetworks.hard.reserved', 'a reserved address')
  }
}

function verdictBadge(a: DestinationAddress, t: TFn) {
  switch (a.verdict) {
    case 'allowed':
      return (
        <Badge variant="secondary">{t('admin.privateNetworks.verdict.allowed', 'Reachable')}</Badge>
      )
    case 'allowed_private':
      return (
        <Badge variant="secondary">
          {t('admin.privateNetworks.verdict.allowedPrivate', 'Reachable, opened')}
        </Badge>
      )
    case 'blocked_private':
      return (
        <Badge variant="outline">{t('admin.privateNetworks.verdict.blocked', 'Blocked')}</Badge>
      )
    default:
      return (
        <Badge variant="destructive">
          {t('admin.privateNetworks.verdict.hardBlocked', 'Never reachable')}
        </Badge>
      )
  }
}

function verdictText(a: DestinationAddress, t: TFn): string {
  switch (a.verdict) {
    case 'allowed':
      return t('admin.privateNetworks.explain.allowed', 'A public address.')
    case 'allowed_private':
      if (a.all_private_open)
        return t(
          'admin.privateNetworks.explain.allPrivate',
          'Opened by the development switch that opens every private range.'
        )
      return a.source === 'server'
        ? t('admin.privateNetworks.explain.openedServer', 'Opened by {range}, set on the server.', {
            range: a.opened_by ?? '',
          })
        : t('admin.privateNetworks.explain.openedConsole', 'Opened by {range}, listed here.', {
            range: a.opened_by ?? '',
          })
    case 'blocked_private':
      return t(
        'admin.privateNetworks.explain.blocked',
        'A private address no range opens. Adding {range} would open it.',
        { range: a.suggested ?? '' }
      )
    default:
      return t(
        'admin.privateNetworks.explain.hardBlocked',
        'This is {what}; it is never reachable.',
        {
          what: hardBlockText(a.hard_block, t),
        }
      )
  }
}

export interface PrivateDestinationsPanelProps {
  settings: PrivateDestinationsSettings
  canEdit: boolean
  onSaved: () => void
}

/**
 * System > Private networks: the private ranges the platform's outbound
 * requests (webhooks, integrations, CI issuers, mail relays) may reach. The
 * server's ranges are shown read only; the console's are edited here by a
 * platform owner with a reason and a fresh confirmation. A destination test
 * resolves a host name and shows how each address is treated; it never
 * connects.
 */
export function PrivateDestinationsPanel({
  settings,
  canEdit,
  onSaved,
}: PrivateDestinationsPanelProps) {
  const { t } = useTranslation()
  const id = useId()
  const savedRows = useMemo<Row[]>(
    () => settings.ranges.map((r, i) => ({ key: i, cidr: r.cidr, note: r.note ?? '' })),
    [settings.ranges]
  )
  const [rows, setRows] = useState<Row[]>(savedRows)
  const [nextKey, setNextKey] = useState(savedRows.length)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [rowError, setRowError] = useState<{ index: number; text: string } | null>(null)
  const reset = useCallback(() => {
    setRows(savedRows)
    setRowError(null)
  }, [savedRows])
  useEffect(reset, [reset])

  const norm = (list: { cidr: string; note: string }[]) =>
    JSON.stringify(list.map((r) => [r.cidr.trim(), r.note.trim()]))
  const dirty = norm(rows) !== norm(savedRows)
  const draft = rows.filter((r) => r.cidr.trim() !== '' || r.note.trim() !== '')
  const opensMore = draft.some((r) => !savedRows.some((s) => s.cidr === r.cidr.trim()))
  const pending =
    !dirty &&
    JSON.stringify(settings.ranges.map((r) => r.cidr)) !== JSON.stringify(settings.in_force)

  const addRow = (cidr = '') => {
    setRows((rs) => [...rs, { key: nextKey, cidr, note: '' }])
    setNextKey((k) => k + 1)
  }
  const update = (key: number, patch: Partial<Row>) =>
    setRows((rs) => rs.map((r) => (r.key === key ? { ...r, ...patch } : r)))
  const remove = (key: number) => setRows((rs) => rs.filter((r) => r.key !== key))

  const save = async (reason: string) => {
    setRowError(null)
    try {
      await savePrivateDestinations({
        ranges: draft.map((r) => ({ cidr: r.cidr.trim(), note: r.note.trim() || undefined })),
        reason,
        version: settings.version,
      })
      toast.success(t('admin.privateNetworks.saved', 'Private networks saved'))
      onSaved()
    } catch (e) {
      if (
        handleSaveConflict(
          e,
          onSaved,
          t(
            'admin.settings.conflict',
            'Another administrator changed this setting. The latest values are shown.'
          )
        )
      )
        return
      if (e instanceof AdminApiError && e.code === 'PRIVATE_RANGE_INVALID') {
        const d = (e.details ?? {}) as { index?: number; reason?: string }
        const text = rangeReasonText(d.reason, t)
        setRowError({ index: d.index ?? -1, text })
        throw new Error(text)
      }
      throw e
    }
  }

  const rowIndex = (key: number) => draft.findIndex((r) => r.key === key)

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.privateNetworks.title', 'Private network destinations')}</CardTitle>
          <CardDescription>
            {t(
              'admin.privateNetworks.description',
              'Private addresses the platform may connect to, such as a self-managed GitLab or a mail relay on your network. Every organization’s webhooks, integrations and CI connections can reach an address opened here, so open only the hosts the platform needs.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {settings.signup_open && (
            <Alert>
              <AlertTriangle className="size-4" aria-hidden />
              <AlertTitle>
                {t('admin.privateNetworks.signupOpenTitle', 'Closed while sign-up is open')}
              </AlertTitle>
              <AlertDescription>
                {t(
                  'admin.privateNetworks.signupOpenDesc',
                  'Anyone may create an organization on this server (SIGNUP_MODE=open), so no private range can be opened. Ranges can only be removed.'
                )}
              </AlertDescription>
            </Alert>
          )}
          {settings.all_private_open && (
            <Alert>
              <AlertTriangle className="size-4" aria-hidden />
              <AlertTitle>
                {t('admin.privateNetworks.allOpenTitle', 'Every private range is open')}
              </AlertTitle>
              <AlertDescription>
                {t(
                  'admin.privateNetworks.allOpenDesc',
                  'This server runs with the development switch that opens every private range. The list below adds nothing until it is turned off.'
                )}
              </AlertDescription>
            </Alert>
          )}

          <section className="space-y-2" aria-labelledby={`${id}-server`}>
            <h3 id={`${id}-server`} className="text-sm font-medium">
              {t('admin.privateNetworks.serverTitle', 'Set on the server')}
            </h3>
            {settings.server_ranges.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t('admin.privateNetworks.serverNone', 'None.')}
              </p>
            ) : (
              <ul className="flex flex-wrap gap-2" data-testid="server-ranges">
                {settings.server_ranges.map((r) => (
                  <li key={r.cidr}>
                    <Badge variant="outline" className="font-mono">
                      {r.cidr}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
            <p className="text-xs text-muted-foreground">
              {t(
                'admin.privateNetworks.serverHint',
                'Changed only in the server’s environment (OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS) and a restart.'
              )}
            </p>
          </section>

          <section className="space-y-2" aria-labelledby={`${id}-console`}>
            <h3 id={`${id}-console`} className="text-sm font-medium">
              {t('admin.privateNetworks.consoleTitle', 'Opened here')}
            </h3>
            {rows.length === 0 && (
              <p className="text-sm text-muted-foreground">
                {t('admin.privateNetworks.consoleNone', 'No range is opened here.')}
              </p>
            )}
            <ul className="space-y-2" data-testid="console-ranges">
              {rows.map((r) => {
                const idx = rowIndex(r.key)
                const error = rowError && rowError.index === idx ? rowError.text : null
                return (
                  <li key={r.key} className="space-y-1">
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                      <Input
                        value={r.cidr}
                        onChange={(e) => update(r.key, { cidr: e.target.value })}
                        disabled={!canEdit}
                        placeholder="192.168.10.0/24"
                        aria-label={t('admin.privateNetworks.rangeLabel', 'Range')}
                        aria-invalid={!!error}
                        className="font-mono sm:w-56"
                      />
                      <Input
                        value={r.note}
                        onChange={(e) => update(r.key, { note: e.target.value })}
                        disabled={!canEdit}
                        maxLength={100}
                        placeholder={t(
                          'admin.privateNetworks.notePlaceholder',
                          'Note, such as GitLab'
                        )}
                        aria-label={t('admin.privateNetworks.noteLabel', 'Note')}
                        className="sm:flex-1"
                      />
                      {canEdit && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => remove(r.key)}
                          aria-label={t('admin.privateNetworks.remove', 'Remove {range}', {
                            range: r.cidr || t('admin.privateNetworks.rangeLabel', 'Range'),
                          })}
                        >
                          <Trash2 className="size-4" aria-hidden />
                        </Button>
                      )}
                    </div>
                    {error ? (
                      <p className="text-sm text-destructive">{error}</p>
                    ) : (
                      isWideDraft(r.cidr) && (
                        <p className="flex items-center gap-1.5 text-xs text-warning">
                          <AlertTriangle className="size-3.5 shrink-0" aria-hidden />
                          {t(
                            'admin.privateNetworks.wide',
                            'A wide range: every address in it becomes reachable. Prefer the host’s own /32 or its /24.'
                          )}
                        </p>
                      )
                    )}
                  </li>
                )
              })}
            </ul>
            {canEdit && !settings.signup_open && rows.length < settings.max_ranges && (
              <Button variant="outline" size="sm" onClick={() => addRow()}>
                <Plus className="me-1.5 size-4" aria-hidden />
                {t('admin.privateNetworks.add', 'Add range')}
              </Button>
            )}
            {pending && (
              <p className="text-xs text-muted-foreground">
                {t(
                  'admin.privateNetworks.pending',
                  'Saved. Every server applies the list within {seconds} seconds.',
                  { seconds: settings.refresh_seconds }
                )}
              </p>
            )}
          </section>

          <SettingChangedLine change={settings} />
          {canEdit ? (
            <SettingsSaveBar
              className="basis-full"
              dirty={dirty}
              onSave={() => setConfirmOpen(true)}
              onDiscard={reset}
            />
          ) : (
            <RoleRequiredNotice permission={NETWORK_PERMISSION} />
          )}
        </CardContent>
      </Card>

      <DestinationTestCard
        canTest={canEdit}
        onAddRange={canEdit && !settings.signup_open ? addRow : undefined}
      />

      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        destructive={opensMore}
        title={t('admin.privateNetworks.confirmTitle', 'Change the private networks?')}
        desc={t(
          'admin.privateNetworks.confirmDesc',
          'Every organization can reach the listed ranges from the next connection. Recorded in the admin audit log with the old and new lists and sent to every administrator.'
        )}
        confirmText={t('admin.privateNetworks.confirmButton', 'Save private networks')}
        onConfirm={save}
      />
    </>
  )
}

/** Resolves a host name and shows how the platform treats each address. */
function DestinationTestCard({
  canTest,
  onAddRange,
}: {
  canTest: boolean
  onAddRange?: (cidr: string) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const [host, setHost] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<DestinationTestResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      setResult(await testPrivateDestination(host.trim()))
    } catch (e) {
      if (e instanceof AdminApiError && e.code === 'DESTINATION_NOT_A_HOST') {
        setError(
          t(
            'admin.privateNetworks.test.notHost',
            'Enter a host name or an IP address only, such as gitlab.example.com, without https:// or a path.'
          )
        )
      } else if (e instanceof AdminApiError && e.code === 'DESTINATION_NOT_FOUND') {
        setError(
          t('admin.privateNetworks.test.notFound', 'This name does not resolve from the platform.')
        )
      } else if (e instanceof AdminApiError && e.status === 429) {
        setError(
          t('admin.privateNetworks.test.tooMany', 'Too many tests. Wait a minute and try again.')
        )
      } else {
        setError(
          e instanceof Error
            ? e.message
            : t('admin.privateNetworks.test.failed', 'The test failed.')
        )
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('admin.privateNetworks.test.title', 'Test a destination')}</CardTitle>
        <CardDescription>
          {t(
            'admin.privateNetworks.test.description',
            'Checks which addresses a host name resolves to and whether the platform may reach each one. Nothing is sent to the host.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!canTest ? (
          <RoleRequiredNotice permission={NETWORK_PERMISSION} />
        ) : (
          <form
            className="flex flex-col gap-2 sm:flex-row sm:items-end"
            onSubmit={(e) => {
              e.preventDefault()
              if (host.trim()) void run()
            }}
          >
            <div className="space-y-1.5 sm:flex-1">
              <Label htmlFor={id}>{t('admin.privateNetworks.test.hostLabel', 'Host name')}</Label>
              <Input
                id={id}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="gitlab.example.com"
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
              />
            </div>
            <Button type="submit" disabled={busy || !host.trim()}>
              {busy && <Loader2 className="me-1.5 size-4 animate-spin" aria-hidden />}
              {t('admin.privateNetworks.test.run', 'Test')}
            </Button>
          </form>
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
        {result && (
          <div className="space-y-2" data-testid="destination-result">
            {result.name_blocked ? (
              <p className="text-sm">
                {t(
                  'admin.privateNetworks.test.nameBlocked',
                  '{host} is a name the platform never connects to (the host itself or a cloud metadata service).',
                  { host: result.host }
                )}
              </p>
            ) : (
              <ul className="divide-y rounded-lg border">
                {result.addresses.map((a) => (
                  <li
                    key={a.address}
                    className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="break-all font-mono text-sm">{a.address}</span>
                        {verdictBadge(a, t)}
                      </div>
                      <p className="text-sm text-muted-foreground">{verdictText(a, t)}</p>
                    </div>
                    {a.verdict === 'blocked_private' && a.suggested && onAddRange && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="shrink-0"
                        onClick={() => onAddRange(a.suggested ?? '')}
                      >
                        <Plus className="me-1.5 size-4" aria-hidden />
                        {t('admin.privateNetworks.test.addRange', 'Add {range}', {
                          range: a.suggested,
                        })}
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
