'use client'

/**
 * System > Threat intelligence: where the signed vulnerability feed is
 * fetched from (api docs/architecture/feed-transfer.md, "Feed sources in the
 * console"). The release address and the mirrors are changed here by a
 * platform owner with a fresh code and a reason; the server's environment
 * pins them when it sets them. The signing root and the local bundle folder
 * are shown only: they are set on the server, because every downloaded file
 * is checked against the root. "Test fetch" downloads and checks the newest
 * signed pointer at each address without importing anything.
 */

import { useCallback, useEffect, useId, useState } from 'react'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { BreakText } from '@/features/shared/components/break-text'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { TonePill } from '@/features/shared/components/tone-pill'
import { AdminApiError } from '@console/lib/admin-api/client'
import { useFeedRelay } from '../api/use-feed-relay'
import {
  saveVulnFeedSources,
  testVulnFeedSources,
  useVulnFeedSources,
} from '../api/use-platform-settings'
import type { FeedProbeResult, VulnFeedSourcesSettings } from '../types'
import {
  LockedByEnvironment,
  ReasonConfirmDialog,
  SettingChangedLine,
  handleSaveConflict,
} from './console-setting-parts'
import { RoleRequiredNotice } from './role-required-notice'

/** The platform permission that changes the addresses and runs the test. */
export const FEED_SOURCES_PERMISSION = 'platform.settings.feed_sources'

type TFn = ReturnType<typeof useTranslation>['t']

interface Row {
  key: number
  url: string
}

/** The plain words of a test fetch outcome code (blocked_address, not_verified, not_configured). */
export function probeErrorText(r: FeedProbeResult, t: TFn): string {
  switch (r.error) {
    case 'blocked_address':
      return t(
        'admin.feedSources.probe.blocked',
        'The address points to an internal network, which the platform never reaches.'
      )
    case 'not_configured':
      return t(
        'admin.feedSources.probe.notConfigured',
        'The vulnerability feed import is not available on this server.'
      )
    default:
      // not_verified: unreachable, no feed files, an error status or files
      // that do not verify all answer the same, so the test is no probe of
      // which hosts answer (the server log names the cause).
      return t(
        'admin.feedSources.probe.notVerified',
        'No verified feed was found at this address. The server log names the cause.'
      )
  }
}

function SourcesForm({
  settings,
  canEdit,
  relay,
  onSaved,
}: {
  settings: VulnFeedSourcesSettings
  canEdit: boolean
  relay: boolean
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const [base, setBase] = useState(settings.base_url)
  const [rows, setRows] = useState<Row[]>([])
  const [nextKey, setNextKey] = useState(0)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [testing, setTesting] = useState(false)
  const [results, setResults] = useState<FeedProbeResult[] | null>(null)

  const reset = useCallback(() => {
    setBase(settings.base_url)
    setRows(settings.mirrors.map((url, i) => ({ key: i, url })))
    setNextKey(settings.mirrors.length)
  }, [settings])
  useEffect(reset, [reset])

  const mirrors = rows.map((r) => r.url.trim()).filter(Boolean)
  const dirty =
    base.trim().replace(/\/+$/, '') !== settings.base_url ||
    mirrors.length !== settings.mirrors.length ||
    mirrors.some((m, i) => m.replace(/\/+$/, '') !== settings.mirrors[i])
  const editable = canEdit && !settings.locked_by_environment
  const offline = relay || settings.bundle_dir_set

  const addRow = () => {
    setRows((r) => [...r, { key: nextKey, url: '' }])
    setNextKey((k) => k + 1)
  }

  const save = async (reason: string) => {
    try {
      await saveVulnFeedSources({
        base_url: base.trim(),
        mirrors,
        reason,
        version: settings.version,
      })
      toast.success(
        t('admin.feedSources.saved', 'Feed address saved. It applies at the next sync.')
      )
      setResults(null)
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
      throw e
    }
  }

  const runTest = async () => {
    setTesting(true)
    setResults(null)
    try {
      const res = await testVulnFeedSources({ base_url: base.trim(), mirrors })
      setResults(res.results)
    } catch (e) {
      toast.error(
        e instanceof AdminApiError
          ? e.message
          : t('admin.confirm.failed', 'The action failed. Try again.')
      )
    } finally {
      setTesting(false)
    }
  }

  const sourceText =
    settings.source === 'environment'
      ? t('admin.feedSources.sourceEnvironment', 'Set on the server.')
      : settings.source === 'console'
        ? t('admin.feedSources.sourceConsole', 'Set in this console.')
        : t('admin.feedSources.sourceDefault', 'Server default.')

  return (
    <>
      <CardContent className="space-y-5 text-body">
        {settings.locked_by_environment && (
          <LockedByEnvironment envVar={settings.env_vars.join(', ')} />
        )}
        {settings.bundle_dir_set && (
          <p className="text-muted-foreground" data-testid="feed-sources-bundle-dir">
            {t(
              'admin.feedSources.bundleDirInUse',
              'The server reads the feed from a local folder, so these addresses are not used.'
            )}
          </p>
        )}

        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-base`}>
            {t('admin.feedSources.baseLabel', 'Release address')}
          </Label>
          <Input
            id={`${id}-base`}
            value={base}
            onChange={(e) => setBase(e.target.value)}
            disabled={!editable}
            inputMode="url"
            spellCheck={false}
            className="font-mono"
            placeholder="https://"
          />
          <p className="text-cap text-muted-foreground">
            {relay
              ? t(
                  'admin.feedSources.baseHintRelay',
                  'The relay sensors download the feed from this address.'
                )
              : t(
                  'admin.feedSources.baseHint',
                  'Where the platform downloads the feed. https only, no user name, password or query.'
                )}
          </p>
        </div>

        <section className="space-y-2" aria-labelledby={`${id}-mirrors`}>
          <h3 id={`${id}-mirrors`} className="font-medium">
            {t('admin.feedSources.mirrorsTitle', 'Mirrors')}
          </h3>
          <p className="text-cap text-muted-foreground" data-relay={relay ? 'on' : 'off'}>
            {relay
              ? t(
                  'admin.feedSources.mirrorsRelay',
                  'Used in direct mode only. In relay mode the sensors download from the release address.'
                )
              : t(
                  'admin.feedSources.mirrorsHint',
                  'Tried in order when the release address fails. Up to {max}.',
                  { max: settings.max_mirrors }
                )}
          </p>
          {rows.length === 0 && (
            <p className="text-muted-foreground">
              {t('admin.feedSources.mirrorsNone', 'No mirror.')}
            </p>
          )}
          <ul className="space-y-2" data-testid="feed-mirrors">
            {rows.map((r, i) => (
              <li key={r.key} className="flex items-center gap-2">
                <Input
                  value={r.url}
                  onChange={(e) =>
                    setRows((all) =>
                      all.map((x) => (x.key === r.key ? { ...x, url: e.target.value } : x))
                    )
                  }
                  disabled={!editable}
                  inputMode="url"
                  spellCheck={false}
                  placeholder="https://"
                  aria-label={t('admin.feedSources.mirrorLabel', 'Mirror {n}', { n: i + 1 })}
                  className="min-w-0 flex-1 font-mono"
                />
                {editable && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setRows((all) => all.filter((x) => x.key !== r.key))}
                    aria-label={t('admin.feedSources.removeMirror', 'Remove mirror {n}', {
                      n: i + 1,
                    })}
                  >
                    <Trash2 className="size-4" aria-hidden />
                  </Button>
                )}
              </li>
            ))}
          </ul>
          {editable && rows.length < settings.max_mirrors && (
            <Button variant="outline" size="sm" onClick={addRow}>
              <Plus className="me-1.5 size-4" aria-hidden />
              {t('admin.feedSources.addMirror', 'Add mirror')}
            </Button>
          )}
        </section>

        <p className="text-cap text-muted-foreground">{sourceText}</p>

        <section className="space-y-2" aria-labelledby={`${id}-trust`}>
          <h3 id={`${id}-trust`} className="font-medium">
            {t('admin.feedSources.trustTitle', 'Set on the server')}
          </h3>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
            <dt className="text-muted-foreground">
              {t('admin.feedSources.rootLabel', 'Signing root')}
            </dt>
            <dd className="min-w-0" data-testid="feed-root">
              {settings.root_official
                ? t('admin.feedSources.rootOfficial', 'Official root')
                : t('admin.feedSources.rootCustom', 'Custom root (set on the server)')}
              {settings.root_key_id && (
                <span className="block break-all font-mono text-code text-muted-foreground">
                  {settings.root_key_id}
                </span>
              )}
            </dd>
            <dt className="text-muted-foreground">
              {t('admin.feedSources.bundleDirLabel', 'Local feed folder')}
            </dt>
            <dd data-testid="feed-bundle-dir">
              {settings.bundle_dir_set
                ? t('admin.feedSources.bundleDirYes', 'Set on the server: yes')
                : t('admin.feedSources.bundleDirNo', 'Set on the server: no')}
            </dd>
          </dl>
          <p className="text-cap text-muted-foreground">
            {t(
              'admin.feedSources.trustHint',
              'These two are changed only on the server. Every downloaded file is checked against the signing root, so a wrong address can stop the feed but never change what is imported.'
            )}
          </p>
        </section>

        {canEdit && (
          <section className="space-y-2" aria-labelledby={`${id}-test`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 id={`${id}-test`} className="font-medium">
                {t('admin.feedSources.testTitle', 'Check the addresses')}
              </h3>
              <Button
                variant="outline"
                size="sm"
                disabled={testing || offline || !base.trim()}
                onClick={() => void runTest()}
              >
                {testing && <Loader2 className="me-1.5 size-4 animate-spin" />}
                {t('admin.feedSources.testButton', 'Test fetch')}
              </Button>
            </div>
            <p className="text-cap text-muted-foreground">
              {relay
                ? t(
                    'admin.feedSources.testRelay',
                    'Not available in relay mode: the platform makes no outbound request. The relay status above shows each download.'
                  )
                : settings.bundle_dir_set
                  ? t(
                      'admin.feedSources.testBundleDir',
                      'Not available: the server reads the feed from a local folder.'
                    )
                  : t(
                      'admin.feedSources.testHint',
                      'Downloads the newest signed release index from each address above and checks it against the signing root. Nothing is imported or saved.'
                    )}
            </p>
            {results && (
              <ul className="space-y-1.5" data-testid="feed-test-results">
                {results.map((r) => (
                  <li key={r.origin} className="space-y-0.5" data-ok={r.ok ? 'yes' : 'no'}>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <TonePill
                        tone={r.ok ? (r.behind ? 'warning' : 'success') : 'destructive'}
                        state={r.ok ? 'ok' : (r.error ?? 'failed')}
                        label={
                          r.ok
                            ? t('admin.feedSources.probe.ok', 'Verified')
                            : t('admin.feedSources.probe.failed', 'Failed')
                        }
                      />
                      <span className="min-w-0 break-words text-code">
                        <BreakText>{r.origin}</BreakText>
                      </span>
                    </div>
                    <p className="text-muted-foreground">
                      {r.ok
                        ? r.behind
                          ? t(
                              'admin.feedSources.probe.behind',
                              'Release {seq} is older than the one already applied.',
                              { seq: r.sequence ?? 0 }
                            )
                          : t(
                              'admin.feedSources.probe.okDetail',
                              'Release {seq}, signed by the trusted root.',
                              {
                                seq: r.sequence ?? 0,
                              }
                            )
                        : probeErrorText(r, t)}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        <SettingChangedLine change={settings} />
        {canEdit ? (
          !settings.locked_by_environment && (
            <SettingsSaveBar
              className="basis-full"
              dirty={dirty}
              saveDisabled={!base.trim()}
              onSave={() => setConfirmOpen(true)}
              onDiscard={reset}
            />
          )
        ) : (
          <RoleRequiredNotice permission={FEED_SOURCES_PERMISSION} />
        )}
      </CardContent>
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t('admin.feedSources.confirmTitle', 'Change the feed address?')}
        desc={t(
          'admin.feedSources.confirmDesc',
          'Every organization gets its vulnerability data from here from the next sync. Files are still checked against the signing root. Recorded in the admin audit log with the old and new addresses and sent to every administrator.'
        )}
        confirmText={t('admin.feedSources.confirmButton', 'Save feed address')}
        onConfirm={save}
      />
    </>
  )
}

/** The feed address card, beside the feed delivery card. */
export function VulnFeedSourcesCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useVulnFeedSources()
  const relayData = useFeedRelay().data
  const relay = relayData?.mode === 'relay'

  if (error) {
    return (
      <ErrorState
        title={t('admin.feedSources.errorTitle', 'the feed address')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-48 w-full" />

  return (
    <Card data-testid="feed-sources-card">
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
        <div className="min-w-0 space-y-1.5">
          <CardTitle>{t('admin.feedSources.title', 'Vulnerability feed address')}</CardTitle>
          <CardDescription>
            {t(
              'admin.feedSources.description',
              'Where the signed vulnerability feed is downloaded from. A change applies at the next sync, without a restart.'
            )}
          </CardDescription>
        </div>
        {relayData && (
          <TonePill
            tone="muted"
            state={relay ? 'relay' : 'direct'}
            label={
              relay
                ? t('admin.feedRelay.modeRelay', 'Relay')
                : t('admin.feedRelay.modeDirect', 'Direct')
            }
          />
        )}
      </CardHeader>
      <SourcesForm settings={data} canEdit={canEdit} relay={relay} onSaved={() => void mutate()} />
    </Card>
  )
}
