'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanConfig } from '@/lib/api/scan-types'
import { scanDetailHref } from '../lib/scan-link'
import { ScanApprovalBadge } from './approval/scan-approval-badge'

/**
 * The Name cell of the scans list, on one line: the scan name as a link to
 * its page (a plain click opens the detail sheet, a modified or middle click
 * the page in a new tab), then its approval mark. A long name ends in an
 * ellipsis; its full text and the description are in the tooltip, and the
 * description is in the detail sheet.
 */
export function ScanNameCell({
  config,
  onOpen,
}: {
  config: Pick<ScanConfig, 'id' | 'name' | 'description' | 'approval_status'>
  onOpen: () => void
}) {
  const { t } = useTranslation()
  return (
    <div data-slot="scan-name-cell" className="flex min-w-0 items-center gap-2">
      <Link
        href={scanDetailHref(config.id)}
        prefetch={false}
        dir="auto"
        data-slot="scan-name-link"
        title={config.description ? `${config.name}\n${config.description}` : config.name}
        aria-label={t('scans.row.openRow', '{name}, view details', { name: config.name })}
        className="min-w-0 truncate rounded-sm text-start font-medium [unicode-bidi:isolate] hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none focus-visible:ring-inset"
        onClick={(e) => {
          // The row must not open the sheet as well.
          e.stopPropagation()
          if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
          e.preventDefault()
          onOpen()
        }}
      >
        {config.name}
      </Link>
      <ScanApprovalBadge status={config.approval_status} />
    </div>
  )
}
