'use client'

import useSWR from 'swr'
import { useTranslation } from '@/context/i18n-provider'

import { useTenant } from '@/context/tenant-provider'
import { post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  schedulePreviewKey,
  type SchedulePreviewRequest,
  type SchedulePreviewResponse,
} from '../lib/schedule-preview'

/**
 * The next occurrences of a schedule (POST /scans/schedule-preview,
 * scans:read). null skips the request (manual scan, incomplete form).
 *
 * A refused schedule is not a page error: its message is returned as
 * `errorMessage` for the caller to show inline (no toast), because it is the
 * same message saving the scan would give.
 */
export function useSchedulePreview(request: SchedulePreviewRequest | null) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const key =
    request && currentTenant
      ? ['schedule-preview', currentTenant.id, schedulePreviewKey(request)]
      : null
  const { data, error, isLoading } = useSWR<SchedulePreviewResponse>(
    key,
    () => post<SchedulePreviewResponse>(scanEndpoints.schedulePreview(), request),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      keepPreviousData: true,
      dedupingInterval: 60_000,
    }
  )
  return {
    preview: error ? undefined : data,
    isLoading,
    errorMessage: error ? getErrorMessage(error, t('scans.preview.failed')) : null,
  }
}
