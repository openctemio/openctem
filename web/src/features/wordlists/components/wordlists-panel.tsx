'use client'

import { useState } from 'react'
import { ListPlus, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, GatedButton, PageStack, RelativeTime } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'

import {
  deleteWordlist,
  invalidateWordlists,
  updateWordlist,
  useWordlists,
} from '../api/use-wordlists'
import type { Wordlist } from '../types'
import { WordlistDialog } from './wordlist-dialog'
import { WordlistPreviewCard } from './wordlist-preview'

/** Settings, Scanning, Wordlists. Reading needs scans:content:read, changes scans:content:write. */
export function WordlistsPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.ContentPacksRead)
  const canWrite = can(Permission.ContentPacksWrite)
  const { data, error, isLoading, mutate } = useWordlists(canRead)
  const [editing, setEditing] = useState<Wordlist | 'new' | null>(null)
  const [deleting, setDeleting] = useState<Wordlist | null>(null)
  const [toggling, setToggling] = useState<string | null>(null)
  const lists = data?.items ?? []
  const atLimit = !!data && lists.length >= data.limit
  const noWrite = t(
    'wordlists.noWrite',
    'You need the scans:content:write permission to change wordlists'
  )

  if (error) {
    return (
      <ErrorState
        title={t('wordlists.title', 'Wordlists')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading) return <Skeleton className="h-48 w-full" />

  async function toggle(w: Wordlist, enabled: boolean) {
    setToggling(w.id)
    try {
      await updateWordlist(w.id, { enabled })
      await invalidateWordlists()
    } catch (e) {
      toast.error(getErrorMessage(e, t('wordlists.toast.saveFailed', 'Could not save the list')))
    } finally {
      setToggling(null)
    }
  }

  return (
    <PageStack data-testid="wordlists-panel">
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
          <div className="space-y-1">
            <CardTitle className="text-base">{t('wordlists.yours.title', 'Your lists')}</CardTitle>
            <CardDescription>
              {t(
                'wordlists.yours.description',
                'Every enabled list is tried under each of your domains, after the words learned from your own names and before the platform list.'
              )}
            </CardDescription>
          </div>
          <GatedButton
            allowed={canWrite && !atLimit}
            reason={
              canWrite
                ? t('wordlists.atLimit', 'An organization has at most {count} lists', {
                    count: data?.limit ?? 0,
                  })
                : noWrite
            }
            size="sm"
            onClick={() => setEditing('new')}
          >
            <Plus className="size-4" aria-hidden />
            {t('wordlists.new', 'New list')}
          </GatedButton>
        </CardHeader>
        <CardContent>
          {lists.length === 0 ? (
            <EmptyState
              card={false}
              className="py-8"
              icon={ListPlus}
              title={t('wordlists.emptyTitle', 'No lists yet')}
              description={t(
                'wordlists.emptyDescription',
                'Add the words your host names use, such as branch codes, product names or local words. Discovery already uses a platform list and the words learned from your names.'
              )}
            />
          ) : (
            <Table data-testid="wordlists-table">
              <TableHeader>
                <TableRow>
                  <TableHead>{t('wordlists.col.name', 'Name')}</TableHead>
                  <TableHead className="text-end">{t('wordlists.col.labels', 'Labels')}</TableHead>
                  <TableHead className="text-end">
                    {t('wordlists.col.version', 'Version')}
                  </TableHead>
                  <TableHead>{t('wordlists.col.updated', 'Updated')}</TableHead>
                  <TableHead>{t('wordlists.col.enabled', 'In use')}</TableHead>
                  <TableHead>
                    <span className="sr-only">{t('wordlists.col.actions', 'Actions')}</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {lists.map((w) => (
                  <TableRow key={w.id} data-testid="wordlist-row">
                    <TableCell>
                      <div className="font-medium break-words">{w.name}</div>
                      {w.description && (
                        <div className="text-xs text-muted-foreground break-words">
                          {w.description}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-end tabular-nums">
                      {w.lines.toLocaleString()}
                    </TableCell>
                    <TableCell className="text-end">
                      <Badge variant="secondary" className="font-normal tabular-nums">
                        {t('wordlists.versionValue', 'v{version}', { version: w.version })}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <RelativeTime date={w.updated_at} className="text-sm" />
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={w.enabled}
                        disabled={!canWrite || toggling === w.id}
                        onCheckedChange={(v) => void toggle(w, v)}
                        aria-label={t('wordlists.toggleNamed', 'Use {name} in discovery', {
                          name: w.name,
                        })}
                      />
                    </TableCell>
                    <TableCell className="text-end">
                      <div className="flex justify-end gap-2">
                        <GatedButton
                          allowed={canWrite}
                          reason={noWrite}
                          variant="outline"
                          size="sm"
                          onClick={() => setEditing(w)}
                        >
                          {t('wordlists.edit', 'Edit')}
                        </GatedButton>
                        <GatedButton
                          allowed={canWrite}
                          reason={noWrite}
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          aria-label={t('wordlists.deleteNamed', 'Delete {name}', { name: w.name })}
                          onClick={() => setDeleting(w)}
                        >
                          <Trash2 className="size-4" aria-hidden />
                        </GatedButton>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <WordlistPreviewCard />

      {canWrite && (
        <WordlistDialog
          open={!!editing}
          onOpenChange={(o) => !o && setEditing(null)}
          wordlist={editing === 'new' ? null : editing}
        />
      )}

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('wordlists.deleteTitle', 'Delete the list "{name}"?', {
          name: deleting?.name ?? '',
        })}
        desc={t(
          'wordlists.deleteDesc',
          'Discovery runs stop using its labels. Runs that already used it keep their record.'
        )}
        confirmText={t('wordlists.deleteButton', 'Delete list')}
        destructive
        handleConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target) return
          deleteWordlist(target.id)
            .then(async () => {
              toast.success(t('wordlists.toast.deleted', 'List deleted'))
              await invalidateWordlists()
            })
            .catch((e: unknown) =>
              toast.error(
                getErrorMessage(e, t('wordlists.toast.deleteFailed', 'Could not delete the list'))
              )
            )
        }}
      />
    </PageStack>
  )
}
