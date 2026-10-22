/**
 * Files uploaded to a pentest or manual finding.
 * GET /api/v1/attachments?context_type=finding&context_id={id}
 *
 * Goes through the API client (CSRF, tenant and error handling) and surfaces a
 * failure to the caller instead of swallowing it.
 */
import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions/constants'

export interface FindingAttachment {
  id: string
  filename: string
  content_type: string
  size: number
  url: string
  scan_status?: string
  scan_result?: string
}

/** Sources whose findings carry uploaded files. */
const UPLOAD_SOURCES = ['pentest', 'bug_bounty', 'red_team', 'manual']

export function isUploadSource(source: string | undefined): boolean {
  return UPLOAD_SOURCES.includes(source || '')
}

export function findingAttachmentsEndpoint(findingId: string): string {
  return `/api/v1/attachments?context_type=finding&context_id=${encodeURIComponent(findingId)}`
}

export function useFindingAttachments(findingId: string | null, source: string | undefined) {
  const { currentTenant } = useTenant()
  const { hasPermission } = usePermissions()
  // The list needs pentest:findings:read: without it nothing is requested.
  const enabled =
    !!currentTenant &&
    !!findingId &&
    isUploadSource(source) &&
    hasPermission(Permission.PentestFindingsRead)
  return useSWR<{ data?: FindingAttachment[] }>(
    enabled ? findingAttachmentsEndpoint(findingId) : null,
    (url: string) => get<{ data?: FindingAttachment[] }>(url),
    { revalidateOnFocus: false }
  )
}
