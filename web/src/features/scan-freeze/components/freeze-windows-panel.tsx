'use client'

import { useState } from 'react'
import { CalendarClock, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, GatedButton } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'

import {
  deleteFreezeWindow,
  invalidateFreezeWindowsCache,
  useFreezeWindows,
} from '../api/use-freeze-windows'
import { describeSchedule, formatInZone } from '../lib/schedule'
import type { FreezeWindow } from '../types'
import { FreezeWindowDialog } from './freeze-window-dialog'

const NO_WRITE = 'Only owners and administrators can change freeze windows'

interface FreezeWindowsPanelProps {
  /** One zone's windows; omit for the organization-wide windows. */
  zoneId?: string
  zoneName?: string
}

/**
 * The freeze windows of the organization (or of one scan zone): list,
 * create, edit, delete. Writes need sensors:zones:write / delete; the API is
 * the authority, the panel only disables what the caller cannot do.
 */
export function FreezeWindowsPanel({ zoneId, zoneName }: FreezeWindowsPanelProps) {
  const { can } = usePermissions()
  const canWrite = can(Permission.ScanZonesWrite)
  const canDelete = can(Permission.ScanZonesDelete)
  const { data, error, isLoading, mutate } = useFreezeWindows(
    zoneId ? { zoneId } : { tenantWide: true }
  )
  const [editing, setEditing] = useState<FreezeWindow | 'new' | null>(null)
  const [deleting, setDeleting] = useState<FreezeWindow | null>(null)
  const windows = data?.data ?? []

  if (error) return <ErrorState title="freeze windows" error={error} onRetry={() => mutate()} />

  return (
    <div className="space-y-3" data-testid="freeze-windows-panel">
      <div className="flex justify-end">
        <GatedButton
          allowed={canWrite}
          reason={NO_WRITE}
          size="sm"
          onClick={() => setEditing('new')}
        >
          <Plus className="size-4" aria-hidden /> Add freeze window
        </GatedButton>
      </div>
      {isLoading ? (
        <Skeleton className="h-20 w-full" />
      ) : windows.length === 0 ? (
        <EmptyState
          icon={CalendarClock}
          title="No freeze windows"
          description={
            zoneId
              ? 'Add a window to stop active scans of this zone during its maintenance.'
              : 'Add a window to stop every active scan of the organization during maintenance or a change freeze.'
          }
        />
      ) : (
        windows.map((w) => (
          <Card key={w.id} data-testid="freeze-window-row">
            <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
              <div className="min-w-0 space-y-1">
                <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                  {w.name}
                  {w.active ? (
                    <Badge variant="destructive">
                      Active
                      {w.active_until ? ` until ${formatInZone(w.active_until, w.timezone)}` : ''}
                    </Badge>
                  ) : null}
                  {!w.enabled && <Badge variant="secondary">Disabled</Badge>}
                </CardTitle>
                <CardDescription className="break-words">{describeSchedule(w)}</CardDescription>
                {w.description && <p className="text-sm text-muted-foreground">{w.description}</p>}
              </div>
              <div className="flex gap-2">
                <GatedButton
                  allowed={canWrite}
                  reason={NO_WRITE}
                  variant="outline"
                  size="sm"
                  onClick={() => setEditing(w)}
                >
                  Edit
                </GatedButton>
                <GatedButton
                  allowed={canDelete}
                  reason={NO_WRITE}
                  variant="ghost"
                  size="sm"
                  aria-label={`Delete ${w.name}`}
                  onClick={() => setDeleting(w)}
                >
                  <Trash2 className="size-4" aria-hidden />
                </GatedButton>
              </div>
            </CardHeader>
          </Card>
        ))
      )}

      <FreezeWindowDialog
        open={!!editing}
        onOpenChange={(o) => !o && setEditing(null)}
        window={editing === 'new' ? null : editing}
        zoneId={zoneId}
        zoneName={zoneName}
      />

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete freeze window"
        desc={`Delete "${deleting?.name ?? ''}"? Work it holds now is released at once.`}
        confirmText="Delete"
        destructive
        handleConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target) return
          deleteFreezeWindow(target.id ?? '')
            .then(async () => {
              toast.success('Freeze window deleted')
              await invalidateFreezeWindowsCache()
            })
            .catch((e: unknown) => toast.error(getErrorMessage(e, 'Failed to delete the window')))
        }}
      />
    </div>
  )
}
