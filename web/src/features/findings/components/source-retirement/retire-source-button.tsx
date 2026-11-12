'use client'

/**
 * The "Stop using this source" action, the same on every page that shows a
 * source (a finding's "Seen by" rows, a connector integration, a sensor's
 * tool). Shown only with findings:sources:retire; the API stays the
 * authority (it also refuses a caller with narrowed data access).
 */

import { useState } from 'react'
import { Ban } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import type { SourceSelector } from '../../api/source-retirement-api'
import { RetireSourceDialog } from './retire-source-dialog'

export function RetireSourceButton({
  source,
  label,
  onRetired,
  compact = false,
}: {
  source: SourceSelector
  label?: string
  onRetired?: () => void
  /** Icon-only (a row action); the label is the accessible name. */
  compact?: boolean
}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const [open, setOpen] = useState(false)
  if (!can(Permission.FindingsSourcesRetire)) return null
  const text = t('findings.retireSource.button', 'Stop using this source')
  return (
    <>
      <Button
        type="button"
        variant={compact ? 'ghost' : 'outline'}
        size={compact ? 'icon' : 'sm'}
        className={compact ? 'size-7' : undefined}
        aria-label={compact ? text : undefined}
        title={compact ? text : undefined}
        onClick={() => setOpen(true)}
      >
        <Ban className="size-4" aria-hidden />
        {!compact && text}
      </Button>
      {open && (
        <RetireSourceDialog
          open={open}
          onOpenChange={setOpen}
          source={source}
          label={label}
          onRetired={onRetired}
        />
      )}
    </>
  )
}
