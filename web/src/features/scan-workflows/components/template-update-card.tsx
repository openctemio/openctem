'use client'

import { useCallback, useEffect, useState } from 'react'
import { ArrowRight, Loader2, Plus, Sparkles } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission } from '@/lib/permissions'
import {
  addedStepNames,
  applyTemplateUpdate,
  dismissTemplateUpdate,
  fetchTemplateUpdate,
  type TemplateUpdate,
} from '../lib/template-update'

/**
 * "Update available" for a copy of a system template: what the template
 * changed since the copy took it, a preview of each change, and one click to
 * apply it (audited, needs workflow write). Nothing changes without it.
 */
export function TemplateUpdateCard({
  workflowId,
  hasDraft = false,
  onApplied,
}: {
  workflowId: string
  /** An unpublished draft would overwrite the update: apply waits for it. */
  hasDraft?: boolean
  onApplied: () => void
}) {
  const { t } = useTranslation()
  const [update, setUpdate] = useState<TemplateUpdate | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState<'apply' | 'dismiss' | null>(null)

  const load = useCallback(async () => {
    try {
      const u = await fetchTemplateUpdate(workflowId)
      setUpdate(u.available && u.changes.length > 0 ? u : null)
    } catch {
      // No update shown when it cannot be read; the workflow is unchanged.
      setUpdate(null)
    }
  }, [workflowId])

  useEffect(() => {
    void load()
  }, [load])

  if (!update || !update.template_digest) return null
  const digest = update.template_digest
  const added = addedStepNames(update)
  const title =
    added.length > 0
      ? t('workflowStages.templateUpdate.titleAdd', undefined, { steps: added.join(', ') })
      : t('workflowStages.templateUpdate.title')

  const act = async (kind: 'apply' | 'dismiss') => {
    setBusy(kind)
    try {
      if (kind === 'apply') {
        await applyTemplateUpdate(workflowId, digest)
        toast.success(t('workflowStages.templateUpdate.applied'))
        onApplied()
      } else {
        await dismissTemplateUpdate(workflowId, digest)
        toast.success(t('workflowStages.templateUpdate.dismissed'))
      }
      setOpen(false)
      setUpdate(null)
    } catch (err) {
      toast.error(getErrorMessage(err, t('workflowStages.templateUpdate.failed')))
      void load()
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <section
        aria-label={title}
        className="flex flex-wrap items-center gap-2 border-b bg-info/10 px-4 py-2 text-xs"
      >
        <Sparkles className="h-3.5 w-3.5 shrink-0 text-info" aria-hidden />
        <span className="font-medium">{title}</span>
        <span className="text-muted-foreground">
          {t('workflowStages.templateUpdate.from', undefined, {
            template: update.source_template_name ?? '',
          })}
        </span>
        <Button size="sm" variant="outline" className="ms-auto h-7" onClick={() => setOpen(true)}>
          {t('workflowStages.templateUpdate.review')}
        </Button>
      </section>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent size="md">
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{t('workflowStages.templateUpdate.description')}</DialogDescription>
          </DialogHeader>
          <DialogBody>
            <ul
              className="space-y-2 text-sm"
              aria-label={t('workflowStages.templateUpdate.changes')}
            >
              {update.changes.map((c) => (
                <li key={`${c.kind}:${c.step_key}`} className="rounded-md border p-2">
                  {c.kind === 'add_step' ? (
                    <div className="flex items-start gap-2">
                      <Plus className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
                      <div className="min-w-0">
                        <p className="font-medium">
                          {t('workflowStages.templateUpdate.addStep', undefined, {
                            step: c.name || c.step_key,
                          })}
                        </p>
                        {(c.capabilities?.length ?? 0) > 0 && (
                          <p className="text-xs text-muted-foreground break-words">
                            {c.capabilities?.join(', ')}
                          </p>
                        )}
                        <p className="text-xs text-muted-foreground">
                          {c.depends_on.length > 0
                            ? t('workflowStages.templateUpdate.after', undefined, {
                                steps: c.depends_on.join(', '),
                              })
                            : t('workflowStages.templateUpdate.first')}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-start gap-2">
                      <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-info" aria-hidden />
                      <div className="min-w-0">
                        <p className="font-medium">
                          {t('workflowStages.templateUpdate.rewire', undefined, {
                            step: c.name || c.step_key,
                          })}
                        </p>
                        <p className="text-xs text-muted-foreground break-words">
                          <span className="line-through">
                            {(c.depends_on_before ?? []).join(', ') ||
                              t('workflowStages.templateUpdate.nothing')}
                          </span>{' '}
                          → {c.depends_on.join(', ') || t('workflowStages.templateUpdate.nothing')}
                        </p>
                      </div>
                    </div>
                  )}
                </li>
              ))}
            </ul>
            <p className="mt-3 text-xs text-muted-foreground">
              {t('workflowStages.templateUpdate.note')}
            </p>
            {hasDraft && (
              <p role="status" className="mt-2 text-xs text-warning">
                {t('workflowStages.templateUpdate.draftFirst')}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Can permission={Permission.ScanWorkflowsWrite} mode="disable">
              <Button variant="ghost" onClick={() => void act('dismiss')} disabled={busy !== null}>
                {busy === 'dismiss' && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {t('workflowStages.templateUpdate.dismiss')}
              </Button>
            </Can>
            <Can permission={Permission.ScanWorkflowsWrite} mode="disable">
              <Button onClick={() => void act('apply')} disabled={busy !== null || hasDraft}>
                {busy === 'apply' && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {t('workflowStages.templateUpdate.apply')}
              </Button>
            </Can>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
