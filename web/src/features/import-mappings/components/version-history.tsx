'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { Eye } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { importMappingsApi } from '../api/import-mappings-api'
import type {
  MappingDocument,
  MappingVersion,
  MappingVersionSummary,
} from '../types/import-mapping.types'

interface VersionHistoryProps {
  mappingId: string
  versions: MappingVersionSummary[]
  latest: number
  /** Load a version into the editor (people who may save versions). */
  onLoad?: (doc: MappingDocument, version: number) => void
}

/** Every saved version, newest first, each viewable. */
export function VersionHistory({ mappingId, versions, latest, onLoad }: VersionHistoryProps) {
  const { t } = useTranslation()
  const [viewing, setViewing] = useState<MappingVersion | null>(null)
  const [loading, setLoading] = useState<number | null>(null)
  const sorted = [...versions].sort((a, b) => b.version - a.version)

  const view = async (v: number) => {
    setLoading(v)
    try {
      const res = await importMappingsApi.getVersion(mappingId, v)
      setViewing(res.version)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('importMappings.history.loadFailed', 'Could not load the version'))
      )
    } finally {
      setLoading(null)
    }
  }

  return (
    <>
      <ol className="grid gap-2">
        {sorted.map((v) => (
          <li
            key={v.version}
            className="flex flex-wrap items-start justify-between gap-3 rounded-md border bg-card p-3"
          >
            <div className="min-w-0 flex-1 basis-60">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">
                  {t('importMappings.history.version', 'Version {v}', { v: v.version })}
                </span>
                {v.version === latest && (
                  <Badge variant="secondary">{t('importMappings.history.latest', 'Latest')}</Badge>
                )}
                {v.identity_changed && (
                  <Badge variant="outline">
                    {t('importMappings.history.identityChanged', 'Identity changed')}
                  </Badge>
                )}
                <span className="text-xs text-muted-foreground">
                  <RelativeTime date={v.created_at} />
                </span>
              </div>
              {v.note && <p className="mt-1 break-words text-sm">{v.note}</p>}
              <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
                {t('importMappings.history.identity', 'Identity: {members}', {
                  members: v.identity.length ? v.identity.join(', ') : '-',
                })}
                {', '}
                {v.digest.slice(0, 19)}
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => view(v.version)}
              disabled={loading !== null}
            >
              <Eye className="me-1 h-4 w-4" aria-hidden />
              {t('importMappings.history.view', 'View')}
            </Button>
          </li>
        ))}
        {loading !== null && sorted.length === 0 && <Skeleton className="h-16 w-full" />}
      </ol>

      <Dialog open={viewing !== null} onOpenChange={(o) => !o && setViewing(null)}>
        <DialogContent size="xl">
          <DialogHeader>
            <DialogTitle>
              {t('importMappings.history.version', 'Version {v}', { v: viewing?.version ?? 0 })}
            </DialogTitle>
            <DialogDescription className="break-all font-mono text-xs">
              {viewing?.digest}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <pre className="whitespace-pre-wrap break-all rounded bg-muted p-3 text-xs">
              {viewing ? JSON.stringify(viewing.mapping, null, 2) : ''}
            </pre>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setViewing(null)}>
              {t('importMappings.common.close', 'Close')}
            </Button>
            {onLoad && viewing && (
              <Button
                onClick={() => {
                  onLoad(viewing.mapping, viewing.version)
                  setViewing(null)
                }}
              >
                {t('importMappings.history.load', 'Load into the editor')}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
