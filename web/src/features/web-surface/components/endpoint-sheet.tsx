'use client'

import { useState } from 'react'
import Link from 'next/link'
import { EyeOff, Eye, Globe, ListTree, Copy } from 'lucide-react'
import { toast } from 'sonner'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
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
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, useHasPermission } from '@/lib/permissions'
import type { WebEndpointResponse } from '@/lib/api/generated'
import { updateWebEndpoint, useWebEndpoint, useWebEndpointParams } from '../api/use-web-surface'
import { AuthPill, CatalogBadge, ExcludedBadge, MethodBadge, PathText } from './web-surface-badges'

const RISK_LABEL: Record<string, string> = {
  ssrf_candidate: 'SSRF candidate',
  redirect: 'Open redirect candidate',
  idor_candidate: 'IDOR candidate',
  file_path: 'File path',
}

const SOURCE_LABEL: Record<string, string> = {
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
      toast.success(next.state === 'ignored' ? 'Endpoint ignored' : 'Endpoint restored')
    } catch {
      toast.error('Could not update the endpoint')
    } finally {
      setSaving(false)
    }
  }

  const list = params?.data ?? []

  return (
    <Sheet open={endpointId !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="w-full gap-0 p-0 sm:max-w-xl">
        <SheetTitle className="sr-only">Web endpoint</SheetTitle>
        <SheetDescription className="sr-only">
          The endpoint, how it was found and its parameter names.
        </SheetDescription>
        <SheetDetailToolbar title="Web endpoint" onClose={onClose} />
        {isLoading || !ep ? (
          <div className="space-y-3 p-6">
            <Skeleton className="h-6 w-2/3" />
            <Skeleton className="h-4 w-1/2" />
            <Skeleton className="h-24 w-full" />
          </div>
        ) : (
          <div className="overflow-y-auto pb-6">
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
                        <Eye className="mr-1.5 h-4 w-4" /> Restore
                      </>
                    ) : (
                      <>
                        <EyeOff className="mr-1.5 h-4 w-4" /> Ignore
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
                  title="Never tested"
                  actions={
                    <Button variant="outline" size="sm" asChild>
                      <Link href="/scope-config?tab=exclusions">Open the exclusion</Link>
                    </Button>
                  }
                >
                  This endpoint lies under a scope exclusion: it was found without requesting it (a
                  link, a script, a sitemap or a spec) and no scan sends anything there. No findings
                  here does not mean it is safe. An approver can set the exclusion to read-only or
                  allowed testing for a window.
                </DetailCallout>
              )}
              <DetailSection title="Endpoint">
                <DetailFieldGrid>
                  <DetailField label="Origin">
                    <Link href={`/assets/${ep.origin_asset_id}`} className="hover:underline">
                      {ep.origin}
                    </Link>
                  </DetailField>
                  <DetailField label="Example path">
                    <span className="inline-flex items-center gap-1">
                      <PathText path={ep.example_path} />
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6"
                        aria-label="Copy the example path"
                        onClick={() => {
                          void copyToClipboard(ep.example_path ?? '').then(() =>
                            toast.success('Copied')
                          )
                        }}
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </Button>
                    </span>
                  </DetailField>
                  <DetailField label="Kind">
                    <span className="capitalize">{ep.kind}</span>
                  </DetailField>
                  <DetailField label="Last status">{ep.last_status || undefined}</DetailField>
                  <DetailField label="Content type">{ep.content_type || undefined}</DetailField>
                  <DetailField label="Found by">
                    {(ep.sources ?? []).map((s) => SOURCE_LABEL[s] ?? s).join(', ') || undefined}
                  </DetailField>
                  <DetailField label="Technologies">
                    {(ep.technologies ?? []).join(', ') || undefined}
                  </DetailField>
                  <DetailField label="Labels">
                    {(ep.labels ?? []).join(', ') || undefined}
                  </DetailField>
                  <DetailField label="First seen">
                    <RelativeTime date={ep.first_seen_at} />
                  </DetailField>
                  <DetailField label="Last seen">
                    <RelativeTime date={ep.last_seen_at} />
                  </DetailField>
                  <DetailField label="Last changed">
                    {ep.last_changed_at ? <RelativeTime date={ep.last_changed_at} /> : undefined}
                  </DetailField>
                  <DetailField label="Last tool">{ep.last_tool || undefined}</DetailField>
                </DetailFieldGrid>
              </DetailSection>
              <DetailSection title="Parameters" icon={ListTree} count={list.length}>
                {paramsLoading ? (
                  <Skeleton className="h-16 w-full" />
                ) : list.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No parameters seen.</p>
                ) : (
                  <ul className="divide-y rounded-md border" aria-label="Parameters">
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
                          <span className="text-xs text-muted-foreground">required</span>
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
                            {RISK_LABEL[r] ?? r}
                          </Badge>
                        ))}
                      </li>
                    ))}
                  </ul>
                )}
                <p className="text-xs text-muted-foreground">
                  Names only: parameter values are never stored.
                </p>
              </DetailSection>
            </DetailSections>
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}
