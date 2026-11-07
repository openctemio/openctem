'use client'

/**
 * "Paste a list" on the New / Edit scan Targets step: an inline panel (not a
 * nested dialog) around the shared paste source. The person pastes or uploads
 * a list, sees what it holds (kinds, repeats, entries that will not be added,
 * to fix or remove) and adds it in one go. Targets already in the scan are
 * not added twice, and the panel says how many still fit under the scan's
 * limit before anything is added. Design: research/418.
 */

import { useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { PasteSource } from '../target-picker/paste-source'
import { parsePastedTargets } from '../../lib/target-format'
import { MAX_DIRECT_TARGETS } from '../../lib/scan-form'

interface BulkTargetsPanelProps {
  id: string
  /** Keys (targetKey) of the targets already in the scan. */
  present: readonly string[]
  /** Direct targets the scan can still take. */
  capacity: number
  /** The organization's widest range, in host bits (default: the API's limit). */
  maxHostBits?: number
  onAdd: (targets: string[]) => void
  onCancel: () => void
}

export function BulkTargetsPanel({
  id,
  present,
  capacity,
  maxHostBits,
  onAdd,
  onCancel,
}: BulkTargetsPanelProps) {
  const { t } = useTranslation()
  const [lines, setLines] = useState<string[]>([])
  const parsed = useMemo(() => parsePastedTargets(lines, { maxHostBits }), [lines, maxHostBits])
  const already = useMemo(() => new Set(present), [present])
  const fresh = parsed.targets.filter((x) => !already.has(x.toLowerCase()))
  const repeated = parsed.targets.length - fresh.length
  const over = fresh.length > capacity

  return (
    <section
      id={id}
      className="min-w-0 space-y-3 rounded-lg border p-3 sm:p-4"
      aria-label={t('scans.bulk.title')}
      data-testid="bulk-panel"
      onKeyDown={(e) => {
        // Ctrl/Cmd+Enter inside the panel adds the list (not the scan).
        if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
          e.preventDefault()
          e.stopPropagation()
          if (fresh.length > 0 && !over) onAdd(fresh)
        }
      }}
    >
      <PasteSource id={`${id}-text`} value={lines} onChange={setLines} rows={5} />
      {repeated > 0 && (
        <p className="text-xs text-muted-foreground">
          {t('scans.bulk.alreadyIn', undefined, { count: repeated })}
        </p>
      )}
      {over && (
        <p role="alert" className="text-xs text-destructive" id={`${id}-over`}>
          {t('scans.bulk.overLimit', undefined, {
            count: fresh.length.toLocaleString(),
            room: capacity.toLocaleString(),
            max: MAX_DIRECT_TARGETS.toLocaleString(),
          })}
        </p>
      )}
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onCancel}>
          {t('scans.bulk.cancel')}
        </Button>
        <Button
          type="button"
          onClick={() => onAdd(fresh)}
          disabled={fresh.length === 0 || over}
          aria-describedby={over ? `${id}-over` : undefined}
          data-testid="bulk-add"
        >
          {t('scans.bulk.add', undefined, { count: fresh.length })}
        </Button>
      </div>
    </section>
  )
}
