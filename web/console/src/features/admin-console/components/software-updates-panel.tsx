'use client'

import { useId, useState } from 'react'
import { Upload } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { SafeExternalLink } from '@/components/safe-external-link'
import { RelativeTime } from '@/features/shared'
import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '@console/lib/admin-api/client'
import { importReleaseFeed } from '../api/use-version-check'
import type { ReleaseFeedAdvisory, VersionCheckErrorCode, VersionCheckStatus } from '../types'

/** The largest file the API accepts (releasefeed.MaxBundleBytes). */
export const MAX_RELEASE_FEED_BYTES = 256 * 1024

const RELEASE_HOSTS = new Set(['openctem.io', 'docs.openctem.io', 'github.com'])

/**
 * A feed link, only when it points at our own pages (the API already refuses
 * anything else; this keeps the console from ever rendering another host).
 */
export function releaseLink(url: string | undefined): string | undefined {
  if (!url) return undefined
  try {
    const u = new URL(url)
    if (
      u.protocol !== 'https:' ||
      u.username ||
      u.password ||
      u.port ||
      !RELEASE_HOSTS.has(u.hostname)
    ) {
      return undefined
    }
    if (u.hostname === 'github.com' && !u.pathname.startsWith('/openctemio/')) return undefined
    return u.toString()
  } catch {
    return undefined
  }
}

const SEVERITY_TONE: Record<ReleaseFeedAdvisory['severity'], PillTone> = {
  critical: 'destructive',
  high: 'destructive',
  medium: 'warning',
  low: 'info',
}

const ERROR_FALLBACK: Record<VersionCheckErrorCode, string> = {
  unreachable: 'The release feed could not be reached (no internet access?).',
  http_status: 'The release feed host answered with an error.',
  too_large: 'The file is larger than a release feed can be.',
  invalid: 'Not a valid signed release feed.',
  rollback: 'Older than the release information already applied.',
  conflict: 'Another release feed with the same sequence is already applied.',
  expired: 'The release feed has expired; get a current copy.',
  no_key: 'This build pins no release feed key.',
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </>
  )
}

/** The file's text (FileReader where Blob.text is missing). */
function readText(file: File): Promise<string> {
  if (typeof file.text === 'function') return file.text()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(file)
  })
}

const COMPONENT_FALLBACK: Record<string, string> = {
  sensor: 'Scanning sensor',
  'connector-tenable': 'Tenable.sc connector',
  sdk: 'Sensor SDK (sdk-go)',
}

function dateOnly(iso: string | undefined) {
  return iso ? new Date(iso).toLocaleDateString() : '-'
}

interface Props {
  status: VersionCheckStatus
  canImport: boolean
  onChanged: () => void
}

/**
 * System -> Software updates (RFC-105): what the signed release feed says
 * about this instance, where the information came from, and the offline
 * import for instances without internet access.
 */
export function SoftwareUpdatesPanel({ status, canImport, onChanged }: Props) {
  const { t } = useTranslation()
  const fileId = useId()
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)

  const errorText = (code: VersionCheckErrorCode) =>
    t(`admin.versionCheck.error.${code}`, ERROR_FALLBACK[code])

  // A component the console has no name for (a product added later) shows
  // its id.
  const componentName = (id: string) =>
    COMPONENT_FALLBACK[id]
      ? t(`admin.versionCheck.components.name.${id}`, COMPONENT_FALLBACK[id])
      : id

  const doImport = async () => {
    if (!file) return
    if (file.size > MAX_RELEASE_FEED_BYTES) {
      toast.error(errorText('too_large'))
      return
    }
    setBusy(true)
    try {
      let body: unknown
      try {
        body = JSON.parse(await readText(file))
      } catch {
        toast.error(errorText('invalid'))
        return
      }
      await importReleaseFeed(body)
      toast.success(t('admin.versionCheck.import.done', 'Release information imported.'))
      setFile(null)
      onChanged()
    } catch (err) {
      const code =
        err instanceof AdminApiError
          ? err.code?.replace(/^RELEASE_FEED_/, '').toLowerCase()
          : undefined
      toast.error(
        code && code in ERROR_FALLBACK
          ? errorText(code as VersionCheckErrorCode)
          : err instanceof AdminApiError
            ? err.message
            : t('admin.confirm.failed', 'The action failed. Try again.')
      )
    } finally {
      setBusy(false)
    }
  }

  let stateTone: PillTone = 'muted'
  let stateLabel = t('admin.versionCheck.state.unknown', 'No release information')
  if (status.source && status.comparable) {
    if (status.advisories.length > 0) {
      stateTone = 'destructive'
      stateLabel = t('admin.versionCheck.state.security', 'Security release available')
    } else if (status.update_available) {
      stateTone = 'info'
      stateLabel = t('admin.versionCheck.state.update', 'Update available')
    } else {
      stateTone = 'success'
      stateLabel = t('admin.versionCheck.state.current', 'Up to date')
    }
  } else if (status.source) {
    stateLabel = t('admin.versionCheck.state.notComparable', 'This build has no release version')
  }

  return (
    <div className="grid gap-4">
      {!status.configured && (
        <Alert>
          <AlertTitle>
            {t(
              'admin.versionCheck.notConfigured.title',
              'Release checks are not active in this build'
            )}
          </AlertTitle>
          <AlertDescription>
            {t(
              'admin.versionCheck.notConfigured.body',
              'This build pins no key for the signed release feed, so it does not check for releases and cannot verify an imported file.'
            )}
          </AlertDescription>
        </Alert>
      )}
      {status.stale && status.feed_expires_at && (
        <Alert variant="destructive">
          <AlertTitle>
            {t('admin.versionCheck.stale.title', 'The release information is out of date')}
          </AlertTitle>
          <AlertDescription>
            {t(
              'admin.versionCheck.stale.body',
              'It was valid until {date}. Newer releases or advisories may be missing.',
              { date: dateOnly(status.feed_expires_at) }
            )}
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
          <div className="space-y-1">
            <CardTitle className="text-base">
              {t('admin.versionCheck.statusTitle', 'This instance')}
            </CardTitle>
            <TonePill tone={stateTone} label={stateLabel} />
          </div>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
            <Field label={t('admin.versionCheck.running', 'Running version')}>
              <span className="font-mono">{status.running}</span>
            </Field>
            <Field label={t('admin.versionCheck.latest', 'Latest release')}>
              <span className="font-mono">{status.latest ?? '-'}</span>
            </Field>
            <Field label={t('admin.versionCheck.sourceLabel', 'Information from')}>
              {status.source === 'online'
                ? t('admin.versionCheck.source.online', 'Daily online check')
                : status.source === 'import'
                  ? t('admin.versionCheck.source.import', 'Imported file')
                  : '-'}
              {status.applied_at && (
                <>
                  {' · '}
                  <RelativeTime date={status.applied_at} />
                </>
              )}
            </Field>
            <Field label={t('admin.versionCheck.validUntil', 'Valid until')}>
              {dateOnly(status.feed_expires_at)}
            </Field>
            <Field label={t('admin.versionCheck.onlineCheck', 'Online check')}>
              {status.enabled
                ? t(
                    'admin.versionCheck.online.on',
                    'On (once a day, no data about this instance is sent)'
                  )
                : t('admin.versionCheck.online.off', 'Off (VERSION_CHECK_ENABLED=false)')}
            </Field>
            {status.enabled && status.configured && (
              <>
                <Field label={t('admin.versionCheck.lastCheck', 'Last check')}>
                  {status.last_attempt_at ? <RelativeTime date={status.last_attempt_at} /> : '-'}
                  {status.last_error && (
                    <span className="block text-destructive">{errorText(status.last_error)}</span>
                  )}
                </Field>
                <Field label={t('admin.versionCheck.nextCheck', 'Next check')}>
                  {status.next_check_at ? <RelativeTime date={status.next_check_at} /> : '-'}
                </Field>
              </>
            )}
          </dl>
        </CardContent>
      </Card>

      {status.advisories.length > 0 && (
        <Card className="border-destructive/50">
          <CardHeader>
            <CardTitle className="text-base">
              {t('admin.versionCheck.advisoriesTitle', 'Security advisories affecting {running}', {
                running: status.running,
              })}
            </CardTitle>
            <CardDescription>
              {t(
                'admin.versionCheck.advisoriesHint',
                'Upgrade to {version} or later to fix all of them.',
                {
                  version: status.fixed_in ?? '',
                }
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              {status.advisories.map((a) => {
                const link = releaseLink(a.url)
                return (
                  <li
                    key={a.id}
                    className="flex flex-col gap-1 py-2 sm:flex-row sm:items-center sm:gap-3"
                  >
                    <TonePill
                      tone={SEVERITY_TONE[a.severity]}
                      label={t(`severity.${a.severity}`, a.severity)}
                    />
                    <div className="min-w-0 flex-1 text-sm">
                      <p className="font-medium break-words">
                        {link ? (
                          <SafeExternalLink href={link} className="underline underline-offset-4">
                            {a.title}
                          </SafeExternalLink>
                        ) : (
                          a.title
                        )}
                      </p>
                      <p className="text-muted-foreground">
                        {t('admin.versionCheck.advisoryMeta', '{id} · fixed in {version}', {
                          id: a.id,
                          version: a.fixed_in,
                        })}
                      </p>
                    </div>
                  </li>
                )
              })}
            </ul>
          </CardContent>
        </Card>
      )}

      {status.newer.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t('admin.versionCheck.newerTitle', 'Newer releases')}
            </CardTitle>
            <CardDescription>
              {t(
                'admin.versionCheck.newerHint',
                'Read the upgrade notes of each release before upgrading. Upgrading is always your action; nothing is downloaded or installed automatically.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y text-sm">
              {status.newer.map((r) => {
                const link = releaseLink(r.notes_url)
                return (
                  <li key={r.version} className="flex items-center justify-between gap-3 py-2">
                    <span className="font-mono">
                      {link ? (
                        <SafeExternalLink href={link} className="underline underline-offset-4">
                          {r.version}
                        </SafeExternalLink>
                      ) : (
                        r.version
                      )}
                    </span>
                    <span className="text-muted-foreground">{dateOnly(r.published_at)}</span>
                  </li>
                )
              })}
            </ul>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('admin.versionCheck.components.title', 'Sensors and SDK')}
          </CardTitle>
          <CardDescription>
            {t(
              'admin.versionCheck.components.hint',
              'The newest sensor and SDK releases. Organizations see them as "update available" and the install commands use them, without an upgrade of this instance.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {(status.components ?? []).length === 0 ? (
            <p className="text-muted-foreground text-sm">
              {t(
                'admin.versionCheck.components.none',
                'No release information yet: the versions this release was built with apply, and they may be outdated.'
              )}
            </p>
          ) : (
            <ul className="divide-y text-sm">
              {(status.components ?? []).map((c) => {
                const link = releaseLink(c.notes_url)
                return (
                  <li
                    key={c.component}
                    className="flex flex-wrap items-center justify-between gap-3 py-2"
                  >
                    <span>{componentName(c.component)}</span>
                    <span className="flex items-center gap-3">
                      <span className="font-mono">
                        {link ? (
                          <SafeExternalLink href={link} className="underline underline-offset-4">
                            {c.version}
                          </SafeExternalLink>
                        ) : (
                          c.version
                        )}
                      </span>
                      <span className="text-muted-foreground">{dateOnly(c.published_at)}</span>
                    </span>
                  </li>
                )
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      {canImport && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t('admin.versionCheck.import.title', 'Import release information')}
            </CardTitle>
            <CardDescription>
              {t(
                'admin.versionCheck.import.hint',
                'For an instance without internet access: download openctem-releases.json from the latest release on a connected machine and upload it here. It is verified like the online check.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="min-w-0 flex-1 space-y-1.5">
              <Label htmlFor={fileId}>
                {t('admin.versionCheck.import.file', 'Release feed file (JSON, up to 256 KiB)')}
              </Label>
              <Input
                id={fileId}
                type="file"
                accept=".json,application/json"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </div>
            <Button disabled={!file || busy} onClick={() => void doImport()}>
              <Upload className="me-2 size-4" />
              {t('admin.versionCheck.import.submit', 'Import')}
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
