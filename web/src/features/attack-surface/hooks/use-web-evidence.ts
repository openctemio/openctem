'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import type { WebEvidenceList } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'

/** URL of one capture's screenshot (served by the API as a sandboxed PNG). */
export function webEvidenceScreenshotUrl(assetId: string, evidenceId: string): string {
  return `/api/v1/assets/${encodeURIComponent(assetId)}/web-evidence/${encodeURIComponent(evidenceId)}/screenshot`
}

/**
 * GET /api/v1/assets/{id}/web-evidence (RFC-081): what sensors saw when they
 * fetched the asset. Needs assets:read and the attack_surface module; the
 * API answers 404 outside the caller's data scope.
 */
export function useWebEvidence(assetId: string) {
  const { can } = usePermissions()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()
  const enabled =
    can(Permission.AssetsRead) && !modulesLoading && moduleIds.includes('attack_surface')
  const { data, error, isLoading } = useSWR<WebEvidenceList>(
    enabled && assetId ? `/api/v1/assets/${encodeURIComponent(assetId)}/web-evidence` : null,
    get,
    { revalidateOnFocus: false }
  )
  return { items: data?.items ?? [], error, isLoading }
}
