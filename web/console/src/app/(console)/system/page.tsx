'use client'

import type { ReactNode } from 'react'
import { Main } from '@/components/layout'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { useAdminSystem } from '@console/features/admin-console/api/use-admin-system'
import {
  daysLeft,
  formatBytes,
  hoursAgo,
  levelKey,
  levelTone,
} from '@console/features/admin-console/lib/system'
import type { AdminSystem } from '@console/features/admin-console/types'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 py-1.5">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="flex items-center gap-2 text-sm tabular-nums">{children}</dd>
    </div>
  )
}

function Body({ s }: { s: AdminSystem }) {
  const { t } = useTranslation()
  const levelLabel = (level: number) => t(`admin.system.level.${levelKey(level)}`, levelKey(level))

  const serviceState = (sv: AdminSystem['services'][number]): { tone: PillTone; label: string } => {
    if (!sv.configured)
      return { tone: 'muted', label: t('admin.system.notConfigured', 'Not configured') }
    if (sv.ok) return { tone: 'success', label: t('admin.system.ok', 'OK') }
    return {
      tone: 'destructive',
      label: t(`admin.system.code.${sv.code ?? 'unreachable'}`, sv.code ?? 'unreachable'),
    }
  }

  const b = s.backup
  const backupHours = hoursAgo(b.age_seconds)
  const check = s.version.check

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-2">
        <Section title={t('admin.system.services', 'Services')}>
          <dl className="divide-y">
            {s.services.map((sv) => {
              const st = serviceState(sv)
              return (
                <Row key={sv.name} label={t(`admin.system.service.${sv.name}`, sv.name)}>
                  {sv.name === 'sensors' && sv.configured && (
                    <span className="text-muted-foreground">
                      {t('admin.system.sensorsOnline', '{n} online', { n: sv.detail ?? 0 })}
                    </span>
                  )}
                  {sv.name !== 'sensors' && sv.configured && sv.ok && sv.latency_ms > 0 && (
                    <span className="text-muted-foreground">
                      {t('admin.system.latency', '{ms} ms', { ms: sv.latency_ms.toFixed(1) })}
                    </span>
                  )}
                  <TonePill tone={st.tone} label={st.label} />
                </Row>
              )
            })}
          </dl>
        </Section>

        <Section title={t('admin.system.storage', 'Storage')}>
          {s.storage.volumes.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('admin.system.noVolumes', 'No data volume is configured.')}
            </p>
          ) : (
            <dl className="divide-y">
              {s.storage.volumes.map((v) => (
                <Row key={v.name} label={v.name}>
                  {v.ok ? (
                    <>
                      <span className="text-muted-foreground">
                        {t('admin.system.freeOf', '{free} free of {total}', {
                          free: formatBytes(v.free_bytes),
                          total: formatBytes(v.total_bytes),
                        })}
                      </span>
                      <TonePill
                        tone={levelTone(v.level)}
                        label={t('admin.system.freePct', '{pct}% free', {
                          pct: Math.round(v.free_ratio * 100),
                        })}
                      />
                    </>
                  ) : (
                    <TonePill
                      tone="muted"
                      label={t('admin.system.code.unreadable', 'Unreadable')}
                    />
                  )}
                </Row>
              ))}
              <Row label={t('admin.system.database', 'Database size')}>
                {s.storage.database_ok ? (
                  formatBytes(s.storage.database_bytes)
                ) : (
                  <TonePill tone="muted" label={t('admin.system.code.unreadable', 'Unreadable')} />
                )}
              </Row>
            </dl>
          )}
          <p className="mt-3 text-xs text-muted-foreground">
            {t(
              'admin.system.storageNote',
              'Warning below 20% free, critical below 10%. Administrators are emailed when a volume crosses a threshold.'
            )}
          </p>
        </Section>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Section title={t('admin.system.backup', 'Backup')}>
          {b.reported && b.last_success_at ? (
            <dl className="divide-y">
              <Row label={t('admin.system.lastBackup', 'Last successful backup')}>
                <RelativeTime date={b.last_success_at} />
                <TonePill
                  tone={levelTone(b.level)}
                  label={
                    b.level > 0
                      ? t('admin.system.backupStale', 'Older than 26 h')
                      : t('admin.system.ok', 'OK')
                  }
                />
              </Row>
              {backupHours !== null && (
                <Row label={t('admin.system.backupAge', 'Age')}>
                  {t('admin.system.hours', '{n} h', { n: backupHours })}
                </Row>
              )}
              {b.last_failed && (
                <Row label={t('admin.system.lastRun', 'Last run')}>
                  <TonePill tone="warning" label={t('admin.system.backupFailed', 'Failed')} />
                </Row>
              )}
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t(
                'admin.system.backupNotReported',
                'No backup status is reported. Set SYSTEM_BACKUP_STATUS_FILE to the backup job status file.'
              )}
            </p>
          )}
        </Section>

        <Section title={t('admin.system.certificates', 'Certificates')}>
          <dl className="divide-y">
            {s.certificates.length === 0 && (
              <p className="text-sm text-muted-foreground">
                {t('admin.system.noCertificates', 'No certificate is configured.')}
              </p>
            )}
            {s.certificates.map((c) => (
              <Row key={c.name} label={c.name}>
                {c.ok ? (
                  <>
                    <span className="text-muted-foreground">
                      {t('admin.system.expiresIn', 'Expires in {n} days', {
                        n: daysLeft(c.expires_in_seconds) ?? 0,
                      })}
                    </span>
                    <TonePill tone={levelTone(c.level)} label={levelLabel(c.level)} />
                  </>
                ) : (
                  <TonePill tone="muted" label={t('admin.system.code.unreadable', 'Unreadable')} />
                )}
              </Row>
            ))}
          </dl>
        </Section>
      </div>

      <Section title={t('admin.system.version', 'Version')}>
        <dl className="divide-y">
          <Row label={t('admin.system.running', 'Running')}>
            {s.version.running || '-'}
            {s.version.channel && (
              <span className="text-muted-foreground">{s.version.channel}</span>
            )}
          </Row>
          {check && (
            <>
              <Row label={t('admin.system.versionCheck', 'Version check')}>
                {!check.configured ? (
                  <TonePill
                    tone="warning"
                    label={t('admin.system.feed.noKey', 'No release feed key in this build')}
                  />
                ) : !check.enabled ? (
                  <TonePill tone="muted" label={t('admin.system.off', 'Off')} />
                ) : check.last_error ? (
                  <TonePill tone="warning" label={feedErrorLabel(t, check.last_error)} />
                ) : (
                  <TonePill tone="success" label={t('admin.system.ok', 'OK')} />
                )}
                {check.last_attempt_at && <RelativeTime date={check.last_attempt_at} />}
              </Row>
              {check.configured && (
                <Row label={t('admin.system.feed.lastSuccess', 'Last release information')}>
                  {check.applied_at ? (
                    <RelativeTime date={check.applied_at} />
                  ) : (
                    <span className="text-muted-foreground">
                      {t(
                        'admin.system.feed.never',
                        'Never: the versions built into this release apply'
                      )}
                    </span>
                  )}
                </Row>
              )}
              {check.latest && (
                <Row label={t('admin.system.latest', 'Latest release')}>
                  {check.latest}
                  {check.update_available && (
                    <TonePill
                      tone="info"
                      label={t('admin.system.updateAvailable', 'Update available')}
                    />
                  )}
                </Row>
              )}
              {check.advisories > 0 && (
                <Row label={t('admin.system.advisories', 'Advisories for this version')}>
                  <TonePill tone="destructive" label={String(check.advisories)} />
                </Row>
              )}
            </>
          )}
        </dl>
      </Section>
    </div>
  )
}

export default function AdminSystemPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAdminSystem()
  return (
    <Main>
      <PageHeader
        title={t('admin.nav.system', 'System')}
        description={t(
          'admin.system.description',
          'Services, free space, backup, certificates and version of this installation. Read-only: backup, restore and upgrade run from the kit on the host.'
        )}
      >
        {data && (
          <span className="flex items-center gap-2 text-xs text-muted-foreground">
            <TonePill
              tone={levelTone(data.level)}
              label={t(`admin.system.level.${levelKey(data.level)}`, levelKey(data.level))}
            />
            {t('admin.overview.updated', 'Updated')} <RelativeTime date={data.checked_at} />
          </span>
        )}
      </PageHeader>
      <div className="mt-5">
        {error && !data ? (
          <ErrorState title="system" error={error} onRetry={() => void mutate()} />
        ) : isLoading || !data ? (
          <Skeleton className="h-64 w-full" />
        ) : (
          <Body s={data} />
        )}
      </div>
    </Main>
  )
}

/** What a failed version check means, by its code (the API never sends raw upstream text). */
function feedErrorLabel(t: (key: string, fallback: string) => string, code: string): string {
  switch (code) {
    case 'not_published':
      return t('admin.system.feed.notPublished', 'Release feed not published')
    case 'invalid':
    case 'no_key':
      return t('admin.system.feed.invalid', 'Release feed signature invalid')
    case 'unreachable':
      return t('admin.system.feed.unreachable', 'Release feed unreachable')
    case 'expired':
      return t('admin.system.feed.expired', 'Release feed expired')
    default:
      return t('admin.system.checkFailed', 'Last check failed')
  }
}
