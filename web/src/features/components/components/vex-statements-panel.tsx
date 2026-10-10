'use client'

/**
 * The VEX statements about one package: what the organization states about
 * each vulnerability (not affected, affected, fixed, under investigation),
 * for which versions and assets, until when.
 */

import { useState } from 'react'
import { Pencil, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { usePermissions, Permission } from '@/lib/permissions'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import { deleteVexStatement, useVexStatements, type VexStatement } from '../api/vex'
import { useVexLabels } from './vex-labels'
import { VexStatementDialog } from './vex-statement-dialog'

const STATUS_VARIANT: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  not_affected: 'secondary',
  fixed: 'secondary',
  affected: 'destructive',
  under_investigation: 'outline',
}

export function VexStatementsPanel({ productId }: { productId: string }) {
  const { t } = useTranslation()
  const labels = useVexLabels()
  const { can } = usePermissions()
  const canWrite = can(Permission.FindingsApprove)
  const { data, error, isLoading, mutate } = useVexStatements(productId)
  const [editing, setEditing] = useState<VexStatement | null>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [deleting, setDeleting] = useState<VexStatement | null>(null)
  const [busy, setBusy] = useState(false)

  const openNew = () => {
    setEditing(null)
    setDialogOpen(true)
  }

  const confirmDelete = async () => {
    if (!deleting) return
    setBusy(true)
    try {
      const res = await deleteVexStatement(deleting.id)
      toast.success(
        t('components.vex.deleted', 'Statement deleted: {reopened} findings reopened.', {
          reopened: res.applied.reopened,
        })
      )
      setDeleting(null)
      void mutate()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('components.vex.deleteFailed', 'The statement could not be deleted.'))
      )
    } finally {
      setBusy(false)
    }
  }

  const versions = (s: VexStatement) =>
    s.version_range || (s.versions.length > 0 ? s.versions.join(', ') : labels.versionMode('all'))

  const rows = data?.data ?? []

  return (
    <section className="space-y-3" aria-labelledby="vex-heading">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 id="vex-heading" className="text-base font-semibold">
            {t('components.vex.heading', 'VEX statements')}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t(
              'components.vex.help',
              'Statements also apply to findings reported later. A statement for every asset needs access to every asset.'
            )}
          </p>
        </div>
        {canWrite && (
          <Button size="sm" onClick={openNew}>
            <Plus className="me-1 h-4 w-4" aria-hidden />
            {t('components.vex.new', 'New statement')}
          </Button>
        )}
      </div>

      {isLoading && !data ? (
        <Skeleton className="h-24 w-full" />
      ) : error ? (
        <p role="alert" className="text-sm text-destructive">
          {getErrorMessage(
            error,
            t('components.vex.loadFailed', 'The statements could not be loaded.')
          )}
        </p>
      ) : rows.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-md border border-dashed p-8 text-center">
          <ShieldCheck className="h-6 w-6 text-muted-foreground" aria-hidden />
          <p className="text-sm text-muted-foreground">
            {t(
              'components.vex.empty',
              'No statements yet. When a vulnerability does not affect how you use this package, say so here and its findings close.'
            )}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('components.vex.vulnId', 'Vulnerability')}</TableHead>
                <TableHead>{t('components.vex.status', 'Status')}</TableHead>
                <TableHead>{t('components.vex.versions', 'Versions')}</TableHead>
                <TableHead>{t('components.vex.scope', 'Applies to')}</TableHead>
                <TableHead>{t('components.vex.expiryShort', 'Review by')}</TableHead>
                {canWrite && (
                  <TableHead className="text-end">
                    <span className="sr-only">{t('components.vex.actions', 'Actions')}</span>
                  </TableHead>
                )}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="font-mono text-xs">
                    <Link
                      href={`/findings?cve_id=${encodeURIComponent(s.vuln_id)}`}
                      className="hover:underline"
                    >
                      {s.vuln_id}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1">
                      <Badge variant={STATUS_VARIANT[s.status] ?? 'outline'} className="w-fit">
                        {labels.status(s.status)}
                      </Badge>
                      {s.justification && (
                        <span className="text-xs text-muted-foreground">
                          {labels.justification(s.justification)}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{versions(s)}</TableCell>
                  <TableCell className="text-sm">
                    {s.asset_id ? (
                      <Link href={assetDetailHref(s.asset_id)} className="hover:underline">
                        {t('components.vex.oneAsset', 'One asset')}
                      </Link>
                    ) : (
                      t('components.vex.everyAsset', 'Every asset')
                    )}
                    {s.origin === 'document' && (
                      <Badge variant="outline" className="ms-2 font-normal">
                        {t('components.vex.fromDocument', 'Imported')}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">
                    {s.expires_at ? (
                      <span className={s.expired ? 'text-destructive' : undefined}>
                        {formatDateSafe(s.expires_at)}
                        {s.expired && ` (${t('components.vex.expired', 'expired')})`}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">-</span>
                    )}
                  </TableCell>
                  {canWrite && (
                    <TableCell className="text-end">
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={t('components.vex.edit', 'Edit statement {id}', {
                          id: s.vuln_id,
                        })}
                        onClick={() => {
                          setEditing(s)
                          setDialogOpen(true)
                        }}
                      >
                        <Pencil className="h-4 w-4" aria-hidden />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={t('components.vex.delete', 'Delete statement {id}', {
                          id: s.vuln_id,
                        })}
                        onClick={() => setDeleting(s)}
                      >
                        <Trash2 className="h-4 w-4" aria-hidden />
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <VexStatementDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        productId={productId}
        statement={editing}
        onSaved={() => void mutate()}
      />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('components.vex.deleteTitle', 'Delete this statement?')}
        desc={t(
          'components.vex.deleteDesc',
          'Findings the statement closed reopen unless another statement covers them.'
        )}
        confirmText={t('components.vex.deleteConfirm', 'Delete')}
        destructive
        isLoading={busy}
        handleConfirm={confirmDelete}
      />
    </section>
  )
}
