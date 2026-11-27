'use client'

import { useMemo, useState } from 'react'
import Link from '@/components/link'
import { EyeOff, Eye, Globe, ListTree, Copy, Bug } from 'lucide-react'
import { toast } from 'sonner'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { SeverityBadge } from '@/components/ui/severity-badge'
import {
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
  DetailSheetHeader,
  RelativeTime,
  SheetDetailToolbar,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, useHasPermission } from '@/lib/permissions'
import type { WebEndpointResponse } from '@/lib/api/generated'
import { updateWebEndpoint, useWebEndpoint, useWebEndpointParams } from '../api/use-web-surface'
import { useWebPaths } from '../api/use-web-paths'
import { DEFAULT_PATH_FILTERS, type PathFilters } from '../lib/web-paths-url'
import { AuthPill, CatalogBadge, ExcludedBadge, MethodBadge, PathText } from './web-surface-badges'

export const RISK_LABEL: Record<string, string> = {
  ssrf_candidate: 'SSRF candidate',
  redirect: 'Open redirect candidate',
  idor_candidate: 'IDOR candidate',
  file_path: 'File path',
}

export const SOURCE_LABEL: Record<string, string> = {
  crawl: 'Crawl',
  js: 'JavaScript',
  sitemap: 'Sitemap',
  robots: 'robots.txt',
  spec: 'API spec',
  har: 'HAR',
  archive: 'Archive',
  dast: 'DAST',
  probe: 'Probe',
}

/** Risk-hint and discovery-source labels in the active language. */
export function useWebLabels() {
  const { t } = useTranslation()
  return useMemo(
    () => ({
      risk: (k: string) => (RISK_LABEL[k] ? t(`attackSurface.web.risk.${k}`, RISK_LABEL[k]) : k),
      source: (k: string) =>
        SOURCE_LABEL[k] ? t(`attackSurface.web.source.${k}`, SOURCE_LABEL[k]) : k,
    }),
    [t]
  )
}

/** No filter: the findings of a path are listed whatever the tree hides. */
const ALL: PathFilters = { ...DEFAULT_PATH_FILTERS, hideStatic: false, includeGone: true }

/**
 * The open findings whose URL lies at this endpoint's path template. Findings
 * record no HTTP method, so the same list shows for every method of the path;
 * each path is masked like the example path (no token, digest or opaque id).
 */
function PathFindingsSection({ assetId, template }: { assetId: string; template: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useWebPaths(assetId, template, ALL, {
    here: true,
    findings: true,
    perPage: 0,
  })
  const list = data?.node_findings ?? []
  const total = data?.node_finding_total ?? 0
  return (
    <DetailSection
      title={t('attackSurface.web.sheet.findingsAtPath', 'Findings at this path')}
      icon={Bug}
      count={total}
    >
      {isLoading && !data ? (
        <Skeleton className="h-12 w-full" />
      ) : error && !data ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          {t('attackSurface.web.sheet.findingsFailed', 'Could not load the findings at this path.')}
          <Button variant="link" onClick={() => void mutate()}>
            {t('common.retry', 'Retry')}
          </Button>
        </p>
      ) : list.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t('attackSurface.web.sheet.noFindingsAtPath', 'No open findings at this path.')}
        </p>
      ) : (
        <ul
          className="divide-y rounded-md border"
          aria-label={t('attackSurface.web.sheet.findingsAtPath', 'Findings at this path')}
        >
          {list.map((f) => (
            <li key={f.id}>
              <Link
                href={`/findings/${encodeURIComponent(f.id)}`}
                className="flex min-h-11 items-center gap-2 px-3 py-2 text-sm hover:bg-muted"
              >
                <SeverityBadge severity={f.severity} />
                <span className="min-w-0 flex-1">
                  <span className="line-clamp-2">{f.title}</span>
                  <PathText path={f.path} className="text-xs text-muted-foreground" />
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      {total > list.length && (
        <p className="text-xs text-muted-foreground">
          {t(
            'attackSurface.web.sheet.findingsMore',
            'Showing the {shown} most severe of {total}.',
            {
              shown: list.length,
              total,
            }
          )}
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        {t(
          'attackSurface.web.sheet.findingsByPath',
          'Matched by path: findings do not record the method, so every method of this path lists them.'
        )}
      </p>
    </DetailSection>
  )
}

export interface EndpointSheetProps {
  endpointId: string | null
  onClose: () => void
  /** Called after a state change, so the list can refresh. */
  onChanged?: (e: WebEndpointResponse) => void
}

/**
 * One endpoint: where it lives, how it was found, whether it is tested, and
 * its parameter NAMES (the platform never stores a value).
 */
export function EndpointSheet({ endpointId, onClose, onChanged }: EndpointSheetProps) {
  const { t } = useTranslation()
  const labels = useWebLabels()
  const canWrite = useHasPermission(Permission.AssetsWrite)
  const { data: ep, isLoading, mutate } = useWebEndpoint(endpointId)
  const { data: params, isLoading: paramsLoading } = useWebEndpointParams(endpointId)
  const [saving, setSaving] = useState(false)

  const toggleIgnored = async () => {
    if (!ep?.id) return
    setSaving(true)
    try {
      const next = await updateWebEndpoint(ep.id, {
        state: ep.state === 'ignored' ? 'active' : 'ignored',
      })
      await mutate(next, { revalidate: false })
      onChanged?.(next)
      toast.success(
        next.state === 'ignored'
          ? t('attackSurface.web.sheet.ignored', 'Endpoint ignored')
          : t('attackSurface.web.sheet.restored', 'Endpoint restored')
      )
    } catch {
      toast.error(t('attackSurface.web.sheet.updateFailed', 'Could not update the endpoint'))
    } finally {
      setSaving(false)
    }
  }

  const list = params?.data ?? []

  return (
    <Sheet open={endpointId !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" showCloseButton={false} className="w-full sm:max-w-xl">
        {/* The toolbar has the close button; title and description are for assistive tech. */}
        <SheetHeader className="block p-0 sm:p-0">
          <SheetTitle className="sr-only">
            {t('attackSurface.web.sheet.title', 'Web endpoint')}
          </SheetTitle>
          <SheetDescription className="sr-only">
            {t(
              'attackSurface.web.sheet.description',
              'The endpoint, how it was found and its parameter names.'
            )}
          </SheetDescription>
          <SheetDetailToolbar
            title={t('attackSurface.web.sheet.title', 'Web endpoint')}
            onClose={onClose}
          />
        </SheetHeader>
        <SheetBody className="p-0">
          {isLoading || !ep ? (
            <div className="space-y-3 p-6">
              <Skeleton className="h-6 w-2/3" />
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : (
            <div className="pb-6">
              <DetailSheetHeader
                icon={Globe}
                title={
                  <span className="flex flex-wrap items-center gap-2">
                    <MethodBadge method={ep.method} />
                    <PathText path={ep.path_template} />
                  </span>
                }
                subtitle={ep.origin}
                badges={
                  <>
                    <AuthPill state={ep.auth_state} />
                    <CatalogBadge entry={ep.catalog} />
                    {!ep.in_scope && <ExcludedBadge exclusionId={ep.exclusion_id} />}
                    {ep.state !== 'active' && (
                      <Badge variant="secondary" className="font-normal capitalize">
                        {ep.state}
                      </Badge>
                    )}
                  </>
                }
                actions={
                  canWrite ? (
                    <Button variant="outline" size="sm" onClick={toggleIgnored} disabled={saving}>
                      {ep.state === 'ignored' ? (
                        <>
                          <Eye className="mr-1.5 h-4 w-4" />
                          {t('attackSurface.web.sheet.restore', 'Restore')}
                        </>
                      ) : (
                        <>
                          <EyeOff className="mr-1.5 h-4 w-4" />
                          {t('attackSurface.web.sheet.ignore', 'Ignore')}
                        </>
                      )}
                    </Button>
                  ) : undefined
                }
              />
              <DetailSections className="space-y-6 px-4 sm:px-6">
                {!ep.in_scope && (
                  <DetailCallout
                    tone="warning"
                    title={t('attackSurface.web.sheet.neverTested', 'Never tested')}
                    actions={
                      <Button variant="outline" size="sm" asChild>
                        <Link href="/scope?tab=exclusions">
                          {t('attackSurface.web.sheet.openExclusion', 'Open the exclusion')}
                        </Link>
                      </Button>
                    }
                  >
                    {t(
                      'attackSurface.web.sheet.neverTestedBody',
                      'This endpoint lies under a scope exclusion: it was found without requesting it (a link, a script, a sitemap or a spec) and no scan sends anything there. No findings here does not mean it is safe. An approver can set the exclusion to read-only or allowed testing for a window.'
                    )}
                  </DetailCallout>
                )}
                <DetailSection title={t('attackSurface.web.col.endpoint', 'Endpoint')}>
                  <DetailFieldGrid>
                    <DetailField label={t('attackSurface.web.sheet.origin', 'Origin')}>
                      <Link href={`/assets/${ep.origin_asset_id}`} className="hover:underline">
                        {ep.origin}
                      </Link>
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.examplePath', 'Example path')}>
                      <span className="inline-flex items-center gap-1">
                        <PathText path={ep.example_path} />
                        <Button
                          variant="ghost"
                          size="icon"

                          aria-label={t(
                            'attackSurface.web.sheet.copyPath',
                            'Copy the example path'
                          )}
                          onClick={() => {
                            void copyToClipboard(ep.example_path ?? '').then(() =>
                              toast.success(t('attackSurface.web.sheet.copied', 'Copied'))
                            )
                          }}
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </Button>
                      </span>
                    </DetailField>
                    <DetailField label={t('attackSurface.originWeb.csv.kind', 'Kind')}>
                      <span className="capitalize">{ep.kind}</span>
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.lastStatus', 'Last status')}>
                      {ep.last_status || undefined}
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.contentType', 'Content type')}>
                      {ep.content_type || undefined}
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.foundBy', 'Found by')}>
                      {(ep.sources ?? []).map((s) => labels.source(s)).join(', ') || undefined}
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.technologies', 'Technologies')}>
                      {(ep.technologies ?? []).join(', ') || undefined}
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.labels', 'Labels')}>
                      {(ep.labels ?? []).join(', ') || undefined}
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.firstSeen', 'First seen')}>
                      <RelativeTime date={ep.first_seen_at} />
                    </DetailField>
                    <DetailField label={t('attackSurface.web.col.lastSeen', 'Last seen')}>
                      <RelativeTime date={ep.last_seen_at} />
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.lastChanged', 'Last changed')}>
                      {ep.last_changed_at ? <RelativeTime date={ep.last_changed_at} /> : undefined}
                    </DetailField>
                    <DetailField label={t('attackSurface.web.sheet.lastTool', 'Last tool')}>
                      {ep.last_tool || undefined}
                    </DetailField>
                  </DetailFieldGrid>
                </DetailSection>
                {ep.origin_asset_id && ep.path_template && (
                  <PathFindingsSection assetId={ep.origin_asset_id} template={ep.path_template} />
                )}
                <DetailSection
                  title={t('attackSurface.originWeb.tab.parameters', 'Parameters')}
                  icon={ListTree}
                  count={list.length}
                >
                  {paramsLoading ? (
                    <Skeleton className="h-16 w-full" />
                  ) : list.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      {t('attackSurface.web.sheet.noParams', 'No parameters seen.')}
                    </p>
                  ) : (
                    <ul
                      className="divide-y rounded-md border"
                      aria-label={t('attackSurface.originWeb.tab.parameters', 'Parameters')}
                    >
                      {list.map((p) => (
                        <li
                          key={`${p.location}:${p.name}`}
                          className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm"
                        >
                          <Badge variant="secondary" className="font-normal">
                            {p.location}
                          </Badge>
                          <span className="font-mono">{p.name}</span>
                          {p.type_hint && (
                            <span className="text-xs text-muted-foreground">{p.type_hint}</span>
                          )}
                          {p.required && (
                            <span className="text-xs text-muted-foreground">
                              {t('attackSurface.web.sheet.required', 'required')}
                            </span>
                          )}
                          {p.sensitive && (
                            <Badge variant="outline" className="font-normal">
                              {p.sensitive}
                            </Badge>
                          )}
                          {(p.risk_hints ?? []).map((r) => (
                            <Badge
                              key={r}
                              variant="outline"
                              className="border-warning/50 font-normal text-warning"
                            >
                              {labels.risk(r)}
                            </Badge>
                          ))}
                        </li>
                      ))}
                    </ul>
                  )}
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'attackSurface.web.sheet.namesOnly',
                      'Names only: parameter values are never stored.'
                    )}
                  </p>
                </DetailSection>
              </DetailSections>
            </div>
          )}
        </SheetBody>
      </SheetContent>
    </Sheet>
  )
}
