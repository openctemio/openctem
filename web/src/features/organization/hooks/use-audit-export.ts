'use client'

import { useCallback, useState } from 'react'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import { downloadAuditLog, type AuditExportFormat } from '../api/export-audit-logs'
import type { AuditLogFilters } from '../types/audit.types'

/**
 * Export the audit log with the filters the list shows now. Says so when the
 * export holds only the newest events (the API's X-Export-Truncated header).
 */
export function useAuditExport(filters: AuditLogFilters) {
  const { t } = useTranslation()
  const [isExporting, setIsExporting] = useState(false)

  const run = useCallback(
    async (format: AuditExportFormat) => {
      setIsExporting(true)
      try {
        const { truncated } = await downloadAuditLog(format, filters)
        if (truncated) {
          toast.warning(
            t(
              'auditLog.export.truncated',
              'Only the newest 50,000 events were exported; narrow the filters.'
            )
          )
        } else {
          toast.success(t('auditLog.export.done', 'Audit log exported'))
        }
      } catch (err) {
        toast.error(
          getErrorMessage(err) || t('auditLog.export.failed', 'The audit log could not be exported')
        )
      } finally {
        setIsExporting(false)
      }
    },
    [filters, t]
  )

  return { run, isExporting }
}
