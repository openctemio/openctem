'use client'

import { useState } from 'react'
import { Loader2, Pin, PinOff } from 'lucide-react'
import { toast } from 'sonner'
import type { ContentPackageVersion } from '@/lib/api/generated'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  ErrorState,
  RelativeTime,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { pinPackage, useContentPackage } from '../api'
import { packageActions } from '../lib'
import { PackageActionDialog, type PackageActionKind } from './package-action-dialog'
import { CopyValue, LicenseSummary, PermissionSummary } from './permission-summary'

interface Props {
  packageId: string | null
  onClose: () => void
  /** Called after any change, so the lists refresh. */
  onChanged: () => void
}

function VersionDetails({ v }: { v: ContentPackageVersion }) {
  const { t } = useTranslation()
  const prov = v.provenance ?? {}
  return (
    <DetailSections>
      {v.revoked && (
        <DetailCallout
          tone="destructive"
          title={t('contentCatalog.detail.revoked', 'Version {version} is revoked', {
            version: v.version ?? '',
          })}
        >
          {[v.revoke_severity, v.revoke_reason].filter(Boolean).join(': ') ||
            t('contentCatalog.detail.revokedHint', 'It cannot be installed.')}
        </DetailCallout>
      )}
      <DetailSection title={t('contentCatalog.detail.overview', 'Overview')}>
        {v.summary && <p className="text-sm text-muted-foreground">{v.summary}</p>}
        <DetailFieldGrid>
          <DetailField label={t('contentCatalog.col.type', 'Type')}>
            {v.type ? t(`contentCatalog.type.${v.type}`, v.type) : '-'}
          </DetailField>
          <DetailField label={t('contentCatalog.col.origin', 'Origin')}>
            {v.origin ? t(`contentCatalog.origin.${v.origin}`, v.origin) : '-'}
          </DetailField>
          {v.content_kind && (
            <DetailField label={t('contentCatalog.detail.contentKind', 'Content kind')}>
              {v.content_kind}
            </DetailField>
          )}
          <DetailField label={t('contentCatalog.detail.platform', 'Platform release')}>
            <span className="font-mono text-sm">{v.compatibility?.platform || '-'}</span>
          </DetailField>
        </DetailFieldGrid>
      </DetailSection>
      <DetailSection title={t('contentCatalog.detail.permissions', 'Permissions')}>
        <PermissionSummary permissions={v.permissions} />
      </DetailSection>
      <DetailSection title={t('contentCatalog.detail.license', 'License')}>
        <LicenseSummary version={v} />
      </DetailSection>
      <DetailSection
        title={t('contentCatalog.detail.dependencies', 'Dependencies')}
        count={v.dependencies?.length ?? 0}
      >
        {v.dependencies?.length ? (
          <ul className="space-y-1 text-sm">
            {v.dependencies.map((d) => (
              <li key={d.id} className="font-mono text-xs break-all">
                {d.id} {d.version}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">{t('contentCatalog.none', 'None')}</p>
        )}
      </DetailSection>
      <DetailSection title={t('contentCatalog.detail.signatures', 'Signatures and provenance')}>
        <ul
          className="flex flex-wrap gap-1"
          aria-label={t('contentCatalog.detail.signedBy', 'Signed by')}
        >
          {(v.signatures ?? []).map((s) => (
            <li key={s}>
              <Badge variant="secondary">{t(`contentCatalog.signature.${s}`, s)}</Badge>
            </li>
          ))}
        </ul>
        <DetailFieldGrid>
          <DetailField label={t('contentCatalog.detail.publisher', 'Publisher identity')} full>
            <CopyValue
              value={v.publisher_identity}
              label={t('contentCatalog.detail.publisher', 'Publisher identity')}
            />
          </DetailField>
          <DetailField label={t('contentCatalog.detail.issuer', 'Identity issuer')} full>
            <CopyValue
              value={v.publisher_issuer}
              label={t('contentCatalog.detail.issuer', 'Identity issuer')}
            />
          </DetailField>
          <DetailField label={t('contentCatalog.detail.signedAt', 'Signed')}>
            <RelativeTime date={v.publisher_signed_at} />
          </DetailField>
          <DetailField label={t('contentCatalog.detail.manifestDigest', 'Manifest digest')} full>
            <CopyValue
              value={v.manifest_digest}
              label={t('contentCatalog.detail.manifestDigest', 'Manifest digest')}
            />
          </DetailField>
          <DetailField label={t('contentCatalog.detail.artifactDigest', 'Artifact digest')} full>
            <CopyValue
              value={v.artifact?.digest}
              label={t('contentCatalog.detail.artifactDigest', 'Artifact digest')}
            />
          </DetailField>
          {prov.source_repository && (
            <DetailField label={t('contentCatalog.detail.sourceRepo', 'Source repository')} full>
              <CopyValue
                value={`${prov.source_repository}${prov.source_revision ? `@${prov.source_revision}` : ''}`}
                label={t('contentCatalog.detail.sourceRepo', 'Source repository')}
              />
            </DetailField>
          )}
          {prov.build_identity && (
            <DetailField label={t('contentCatalog.detail.build', 'Build identity')} full>
              <CopyValue
                value={prov.build_identity}
                label={t('contentCatalog.detail.build', 'Build identity')}
              />
            </DetailField>
          )}
        </DetailFieldGrid>
      </DetailSection>
    </DetailSections>
  )
}

/** One package: its versions, what each asks for, who signed it, and the actions. */
export function PackageSheet({ packageId, onClose, onChanged }: Props) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const detail = useContentPackage(packageId)
  const [shown, setShown] = useState<string | null>(null)
  const [action, setAction] = useState<PackageActionKind | null>(null)
  const [pinning, setPinning] = useState(false)

  const versions = detail.data?.versions ?? []
  const install = detail.data?.install
  const pending = detail.data?.pending_request
  const installedVersion = install?.installed?.version
  const current =
    versions.find((v) => v.version === shown) ??
    versions.find((v) => v.version === installedVersion) ??
    versions[0]
  const actions = packageActions({
    canInstall: can(Permission.ContentInstall),
    versions,
    install,
    pending,
  })

  const refresh = () => {
    void detail.mutate()
    onChanged()
  }

  async function togglePin() {
    if (!packageId || !install) return
    setPinning(true)
    try {
      await pinPackage(packageId, !install.pinned)
      toast.success(
        install.pinned
          ? t('contentCatalog.action.unpinned', 'Unpinned: automatic updates resume')
          : t('contentCatalog.action.pinned', 'Pinned: automatic updates stop')
      )
      refresh()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('contentCatalog.error.generic', 'The change was refused.'))
      )
    } finally {
      setPinning(false)
    }
  }

  return (
    <>
      <DetailSheet
        open={packageId !== null}
        onOpenChange={(o) => {
          if (!o) {
            setShown(null)
            onClose()
          }
        }}
        width="lg"
        header={
          <DetailHeader
            title={<span className="break-all">{packageId ?? ''}</span>}
            badges={
              <>
                {installedVersion && (
                  <Badge variant="secondary">
                    {t('contentCatalog.installedVersion', 'Installed {version}', {
                      version: installedVersion,
                    })}
                  </Badge>
                )}
                {install?.pinned && (
                  <Badge variant="outline">{t('contentCatalog.pinned', 'Pinned')}</Badge>
                )}
                {install?.status === 'revoked' && (
                  <Badge variant="destructive">{t('contentCatalog.revoked', 'Revoked')}</Badge>
                )}
              </>
            }
            meta={current ? [current.title, current.type] : []}
            onClose={() => {
              setShown(null)
              onClose()
            }}
            actions={
              <>
                {actions.install && (
                  <Button size="sm" onClick={() => setAction('install')}>
                    {t('contentCatalog.action.install', 'Install')}
                  </Button>
                )}
                {actions.update && (
                  <Button size="sm" onClick={() => setAction('update')}>
                    {t('contentCatalog.action.update', 'Update')}
                  </Button>
                )}
                {actions.rollback && (
                  <Button size="sm" variant="outline" onClick={() => setAction('rollback')}>
                    {t('contentCatalog.action.rollback', 'Roll back')}
                  </Button>
                )}
                {actions.pin && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void togglePin()}
                    disabled={pinning}
                  >
                    {pinning ? (
                      <Loader2 className="size-4 animate-spin" aria-hidden />
                    ) : install?.pinned ? (
                      <PinOff className="size-4" aria-hidden />
                    ) : (
                      <Pin className="size-4" aria-hidden />
                    )}
                    {install?.pinned
                      ? t('contentCatalog.action.unpin', 'Unpin')
                      : t('contentCatalog.action.pin', 'Pin')}
                  </Button>
                )}
                {actions.uninstall && (
                  <Button size="sm" variant="outline" onClick={() => setAction('uninstall')}>
                    {t('contentCatalog.action.uninstall', 'Uninstall')}
                  </Button>
                )}
              </>
            }
          />
        }
      >
        {detail.error ? (
          <ErrorState
            title={t('contentCatalog.detail.what', 'the package')}
            error={detail.error}
            onRetry={() => void detail.mutate()}
          />
        ) : !detail.data ? (
          <div className="space-y-3">
            <Skeleton className="h-6 w-1/2" />
            <Skeleton className="h-24 w-full" />
          </div>
        ) : (
          <div className="space-y-5">
            {pending && (
              <DetailCallout
                tone="info"
                title={t('contentCatalog.detail.pending', 'A request is waiting for approval')}
              >
                {t(
                  'contentCatalog.detail.pendingHint',
                  '{action} {version}: no other change can start until it is decided.',
                  {
                    action: t(
                      `contentCatalog.requestAction.${pending.action}`,
                      pending.action ?? ''
                    ),
                    version: pending.target?.version ?? '',
                  }
                )}
              </DetailCallout>
            )}
            <section aria-labelledby="content-versions-heading" className="space-y-2">
              <h3 id="content-versions-heading" className="text-sm font-semibold">
                {t('contentCatalog.detail.versions', 'Versions')}
              </h3>
              <ul className="flex flex-wrap gap-1.5">
                {versions.map((v) => {
                  const active = v.version === current?.version
                  return (
                    <li key={v.version}>
                      <button
                        type="button"
                        aria-pressed={active}
                        onClick={() => setShown(v.version ?? null)}
                        className={cn(
                          'inline-flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                          active ? 'border-primary bg-primary/10' : 'hover:bg-accent',
                          v.revoked && 'text-destructive line-through'
                        )}
                      >
                        {v.version}
                        {v.version === installedVersion && (
                          <span className="font-sans text-[10px] text-muted-foreground">
                            {t('contentCatalog.detail.installedTag', 'installed')}
                          </span>
                        )}
                        {v.revoked && (
                          <span className="sr-only">{t('contentCatalog.revoked', 'Revoked')}</span>
                        )}
                      </button>
                    </li>
                  )
                })}
              </ul>
            </section>
            {current && <VersionDetails v={current} />}
          </div>
        )}
      </DetailSheet>
      {action && packageId && (
        <PackageActionDialog
          key={`${action}-${packageId}`}
          kind={action}
          packageId={packageId}
          versions={versions}
          install={install}
          onOpenChange={(o) => !o && setAction(null)}
          onDone={refresh}
        />
      )}
    </>
  )
}
