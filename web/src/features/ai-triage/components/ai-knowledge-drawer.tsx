'use client'

import { useRef, useState } from 'react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { DetailField, DetailFieldGrid, TonePill } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { toDisplayText } from '@/lib/untrusted-text'

import {
  KNOWLEDGE_MAX_DOCUMENT_BYTES,
  KNOWLEDGE_QUARANTINE_CODE,
  addKnowledgeDocument,
  approveKnowledgeSource,
  deleteKnowledgeDocument,
  deleteKnowledgeSource,
  disableKnowledgeSource,
  previewKnowledge,
  rejectKnowledgeSource,
  useAIKnowledgeSource,
  type KnowledgeDocument,
  type KnowledgeHit,
} from '../api/use-ai-knowledge'
import { useAIAgents } from '../api/use-ai-agents'
import {
  SourceStatusPill,
  dataClassText,
  formatBytes,
  utf8Bytes,
  visibilityText,
} from './ai-knowledge-shared'

type Pending =
  | { kind: 'approve' }
  | { kind: 'quarantine' }
  | { kind: 'reject' }
  | { kind: 'disable' }
  | { kind: 'deleteSource' }
  | { kind: 'deleteDocument'; doc: KnowledgeDocument }

/**
 * Detail drawer of one knowledge source: facts, document versions, adding
 * text, and the approval actions. Document text is plain text only: it is
 * read from a file or textarea and sent, never rendered. Every change needs
 * `ai_knowledge:manage` (`canManage`); the API stays the authority.
 */
export function AIKnowledgeDrawer({
  sourceId,
  canManage,
  onClose,
  onChanged,
}: {
  sourceId: string | null
  canManage: boolean
  onClose: () => void
  onChanged: () => Promise<unknown> | void
}) {
  const { t } = useTranslation()
  const detail = useAIKnowledgeSource(sourceId)
  const src = detail.data
  const [pending, setPending] = useState<Pending | null>(null)
  const [reason, setReason] = useState('')

  const [title, setTitle] = useState('')
  const [text, setText] = useState('')
  const [replaces, setReplaces] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const [selectedId, setSelectedId] = useState('')
  const [query, setQuery] = useState('')
  const [hits, setHits] = useState<KnowledgeHit[] | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const aiAgents = useAIAgents(canManage && !!sourceId)

  const tooLarge = t(
    'settings.ai.knowledge.doc.tooLarge',
    'The document is too large (at most 256 KB).'
  )

  const refresh = async () => {
    await detail.mutate()
    await onChanged()
  }

  const pickFile = async (file: File | undefined) => {
    if (!file) return
    setFormError(null)
    if (file.size > KNOWLEDGE_MAX_DOCUMENT_BYTES) {
      setFormError(tooLarge)
    } else {
      setText(await file.text())
      if (!title.trim()) setTitle(file.name.replace(/\.(md|txt)$/i, ''))
    }
    if (fileRef.current) fileRef.current.value = ''
  }

  const bytes = utf8Bytes(text)
  const overLimit = bytes > KNOWLEDGE_MAX_DOCUMENT_BYTES

  const addDocument = async () => {
    if (!sourceId) return
    if (overLimit) {
      setFormError(tooLarge)
      return
    }
    setAdding(true)
    setFormError(null)
    try {
      await addKnowledgeDocument(sourceId, {
        title: title.trim(),
        text,
        ...(replaces ? { replaces } : {}),
      })
      toast.success(
        t('settings.ai.knowledge.toast.documentAdded', 'Document added, waiting for approval')
      )
      setTitle('')
      setText('')
      setReplaces(null)
      await refresh()
    } catch (err) {
      // The server message is user-safe (a credential's line, the quota).
      setFormError(getErrorMessage(err))
    } finally {
      setAdding(false)
    }
  }

  const runPreview = async () => {
    setPreviewing(true)
    try {
      setHits(await previewKnowledge(selectedId, query.trim()))
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setPreviewing(false)
    }
  }

  const confirmPending = async () => {
    if (!pending || !sourceId) return
    try {
      switch (pending.kind) {
        case 'approve':
        case 'quarantine':
          try {
            await approveKnowledgeSource(sourceId, pending.kind === 'quarantine')
          } catch (err) {
            if (
              pending.kind === 'approve' &&
              err instanceof ApiClientError &&
              err.code === KNOWLEDGE_QUARANTINE_CODE
            ) {
              setPending({ kind: 'quarantine' })
              return
            }
            throw err
          }
          toast.success(t('settings.ai.knowledge.toast.approved', 'Knowledge approved'))
          break
        case 'reject':
          await rejectKnowledgeSource(sourceId, reason.trim())
          toast.success(t('settings.ai.knowledge.toast.rejected', 'Knowledge rejected'))
          setReason('')
          break
        case 'disable':
          await disableKnowledgeSource(sourceId)
          toast.success(t('settings.ai.knowledge.toast.disabled', 'Knowledge source disabled'))
          break
        case 'deleteDocument':
          await deleteKnowledgeDocument(pending.doc.id)
          toast.success(t('settings.ai.knowledge.toast.documentDeleted', 'Document deleted'))
          break
        case 'deleteSource':
          await deleteKnowledgeSource(sourceId)
          toast.success(t('settings.ai.knowledge.toast.deleted', 'Knowledge source deleted'))
          setPending(null)
          await onChanged()
          onClose()
          return
      }
      setPending(null)
      await refresh()
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }

  const hasPending = !!src && (src.status === 'pending' || src.pending_documents > 0)
  const active = !!src && src.status !== 'rejected' && src.status !== 'disabled'
  const name = toDisplayText(src?.name, 80)

  const confirm = (() => {
    switch (pending?.kind) {
      case 'approve':
        return {
          title: t('settings.ai.knowledge.confirm.approveTitle', 'Approve {name}?', { name }),
          desc: t(
            'settings.ai.knowledge.confirm.approveDesc',
            'The text waiting for approval starts reaching the AI agents that may read this source. Review the documents first.'
          ),
          label: t('settings.ai.knowledge.action.approve', 'Approve'),
          destructive: false,
        }
      case 'quarantine':
        return {
          title: t(
            'settings.ai.knowledge.confirm.quarantineTitle',
            'Approve text that looks like instructions?'
          ),
          desc: t(
            'settings.ai.knowledge.confirm.quarantineDesc',
            'Some quarantined text looks like instructions to an AI model. Approving it lets AI agents read it as knowledge. Approve only if you reviewed it and it is safe.'
          ),
          label: t('settings.ai.knowledge.action.approveAnyway', 'Approve anyway'),
          destructive: true,
        }
      case 'reject':
        return {
          title: t('settings.ai.knowledge.confirm.rejectTitle', 'Reject {name}?', { name }),
          desc: t(
            'settings.ai.knowledge.confirm.rejectDesc',
            'The text waiting for approval is rejected and never reaches an AI agent.'
          ),
          label: t('settings.ai.knowledge.action.reject', 'Reject'),
          destructive: true,
        }
      case 'disable':
        return {
          title: t('settings.ai.knowledge.confirm.disableTitle', 'Disable {name}?', { name }),
          desc: t(
            'settings.ai.knowledge.confirm.disableDesc',
            'AI agents stop reading this source. It stays here and can be replaced by a new one.'
          ),
          label: t('settings.ai.knowledge.action.disable', 'Disable'),
          destructive: true,
        }
      case 'deleteSource':
        return {
          title: t('settings.ai.knowledge.confirm.deleteTitle', 'Delete {name}?', { name }),
          desc: t(
            'settings.ai.knowledge.confirm.deleteDesc',
            'The source and every document in it are deleted. Past AI runs keep only the ids and digests of what they cited.'
          ),
          label: t('settings.ai.knowledge.action.delete', 'Delete source'),
          destructive: true,
        }
      case 'deleteDocument':
        return {
          title: t('settings.ai.knowledge.confirm.deleteDocTitle', 'Delete {title}?', {
            title: toDisplayText(pending.doc.title, 80),
          }),
          desc: t(
            'settings.ai.knowledge.confirm.deleteDocDesc',
            'This version of the document is deleted and AI agents no longer cite it.'
          ),
          label: t('settings.ai.knowledge.action.deleteDocument', 'Delete document'),
          destructive: true,
        }
      default:
        return { title: '', desc: '', label: '', destructive: false }
    }
  })()

  return (
    <>
      <Sheet open={!!sourceId} onOpenChange={(o) => !o && onClose()}>
        <SheetContent side="right" className="w-full sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle>{name || t('settings.ai.knowledge.title', 'Knowledge sources')}</SheetTitle>
            <SheetDescription>
              {src?.description
                ? toDisplayText(src.description, 300)
                : t('settings.ai.knowledge.drawer.noDescription', 'No description.')}
            </SheetDescription>
          </SheetHeader>
          <SheetBody className="space-y-6">
            {detail.isLoading ? (
              <Skeleton className="h-24 w-full" />
            ) : detail.error || !src ? (
              <p className="text-sm text-destructive">{getErrorMessage(detail.error)}</p>
            ) : (
              <>
                <DetailFieldGrid>
                  <DetailField label={t('settings.ai.knowledge.col.status', 'Status')}>
                    <SourceStatusPill
                      status={src.status}
                      pendingDocuments={src.pending_documents}
                    />
                  </DetailField>
                  <DetailField label={t('settings.ai.knowledge.col.visibility', 'Visibility')}>
                    {visibilityText(t, src)}
                  </DetailField>
                  <DetailField label={t('settings.ai.knowledge.col.dataClass', 'Data class')}>
                    {dataClassText(t, src.data_class)}
                  </DetailField>
                  <DetailField label={t('settings.ai.knowledge.col.size', 'Size')}>
                    {formatBytes(src.bytes)}
                  </DetailField>
                  {src.status === 'rejected' && src.rejected_reason && (
                    <DetailField
                      full
                      label={t(
                        'settings.ai.knowledge.drawer.rejectedReason',
                        'Reason for rejection'
                      )}
                    >
                      {toDisplayText(src.rejected_reason, 500)}
                    </DetailField>
                  )}
                </DetailFieldGrid>
                {src.self_approved && (
                  <p className="text-sm text-muted-foreground">
                    {t(
                      'settings.ai.knowledge.drawer.selfApproved',
                      'Approved by the organization owner who added it.'
                    )}
                  </p>
                )}

                <section className="space-y-2">
                  <h3 className="text-sm font-medium">
                    {t('settings.ai.knowledge.drawer.documents', 'Documents')}
                  </h3>
                  {src.document_versions.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      {t('settings.ai.knowledge.drawer.noDocuments', 'No documents yet.')}
                    </p>
                  ) : (
                    <ul className="divide-y rounded-md border">
                      {src.document_versions.map((d) => (
                        <li
                          key={d.id}
                          className="space-y-1 p-3 text-sm"
                          data-testid="knowledge-doc"
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-medium">{toDisplayText(d.title, 120)}</span>
                            <span className="text-muted-foreground">
                              {t('settings.ai.knowledge.doc.version', 'Version {n}', {
                                n: d.version,
                              })}
                            </span>
                            <SourceStatusPill status={d.status} />
                            {d.quarantined && (
                              <TonePill
                                tone="warning"
                                label={t('settings.ai.knowledge.doc.quarantined', 'Quarantined')}
                                detail={t(
                                  'settings.ai.knowledge.doc.quarantineReason',
                                  'Looks like instructions to an AI model'
                                )}
                              />
                            )}
                          </div>
                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-muted-foreground">
                            <span>{formatBytes(d.bytes)}</span>
                            <span>
                              {t('settings.ai.knowledge.doc.chunks', '{count} chunks', {
                                count: d.chunks,
                              })}
                            </span>
                            <span>{formatDateSafe(d.created_at)}</span>
                          </div>
                          {canManage && (
                            <div className="flex gap-2 pt-1">
                              {active && d.status !== 'rejected' && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => {
                                    setReplaces(d.id)
                                    setTitle(d.title)
                                    setText('')
                                    setFormError(null)
                                  }}
                                >
                                  {t('settings.ai.knowledge.doc.editAsNew', 'Edit as new version')}
                                </Button>
                              )}
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => setPending({ kind: 'deleteDocument', doc: d })}
                              >
                                {t(
                                  'settings.ai.knowledge.action.deleteDocument',
                                  'Delete document'
                                )}
                              </Button>
                            </div>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </section>

                {canManage && active && (
                  <section className="space-y-3">
                    <h3 className="text-sm font-medium">
                      {replaces
                        ? t('settings.ai.knowledge.add.newVersion', 'New version of a document')
                        : t('settings.ai.knowledge.add.title', 'Add document')}
                    </h3>
                    <div className="grid gap-2">
                      <Label htmlFor="knowledge-doc-title">
                        {t('settings.ai.knowledge.add.docTitle', 'Document title')}
                      </Label>
                      <Input
                        id="knowledge-doc-title"
                        value={title}
                        maxLength={200}
                        onChange={(e) => setTitle(e.target.value)}
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="knowledge-doc-text">
                        {t('settings.ai.knowledge.add.text', 'Text (plain text or Markdown)')}
                      </Label>
                      <Textarea
                        id="knowledge-doc-text"
                        rows={8}
                        value={text}
                        onChange={(e) => {
                          setText(e.target.value)
                          setFormError(null)
                        }}
                      />
                      <p className="text-xs text-muted-foreground">
                        {t(
                          'settings.ai.knowledge.add.hint',
                          '{size} of 256 KB. Do not paste credentials, they are refused. Owners, criticality and SLAs come from assets: do not upload them.',
                          { size: formatBytes(bytes) }
                        )}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <input
                        ref={fileRef}
                        type="file"
                        accept=".md,.txt,text/plain,text/markdown"
                        className="sr-only"
                        aria-label={t(
                          'settings.ai.knowledge.add.file',
                          'Choose a .md or .txt file'
                        )}
                        onChange={(e) => void pickFile(e.target.files?.[0])}
                      />
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => fileRef.current?.click()}
                      >
                        {t('settings.ai.knowledge.add.file', 'Choose a .md or .txt file')}
                      </Button>
                      {replaces && (
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setReplaces(null)
                            setTitle('')
                            setText('')
                          }}
                        >
                          {t('settings.ai.knowledge.add.cancelVersion', 'Add as a new document')}
                        </Button>
                      )}
                    </div>
                    {(formError || overLimit) && (
                      <p role="alert" className="text-sm text-destructive">
                        {formError ?? tooLarge}
                      </p>
                    )}
                    <Button
                      onClick={addDocument}
                      disabled={adding || overLimit || !title.trim() || !text.trim()}
                    >
                      {t('settings.ai.knowledge.add.submit', 'Add document')}
                    </Button>
                  </section>
                )}

                {canManage && (
                  <section className="space-y-3 border-t pt-4">
                    <h3 className="text-sm font-medium">
                      {t('settings.ai.knowledge.preview.title', 'Preview retrieval')}
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      {t(
                        'settings.ai.knowledge.preview.hint',
                        'See which excerpts an AI agent would retrieve for a question. This shows document text.'
                      )}
                    </p>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="grid gap-2">
                        <Label>{t('settings.ai.knowledge.preview.who', 'AI agent')}</Label>
                        <Select value={selectedId} onValueChange={setSelectedId}>
                          <SelectTrigger
                            aria-label={t('settings.ai.knowledge.preview.who', 'AI agent')}
                          >
                            <SelectValue
                              placeholder={t(
                                'settings.ai.knowledge.preview.choose',
                                'Choose an AI agent'
                              )}
                            />
                          </SelectTrigger>
                          <SelectContent>
                            {(aiAgents.data ?? []).map((a) => (
                              <SelectItem key={a.id} value={a.id}>
                                {toDisplayText(a.name, 80)}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="knowledge-preview-query">
                          {t('settings.ai.knowledge.preview.query', 'Question')}
                        </Label>
                        <Input
                          id="knowledge-preview-query"
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                        />
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={previewing || !selectedId || !query.trim()}
                      onClick={runPreview}
                    >
                      {t('settings.ai.knowledge.preview.run', 'Preview')}
                    </Button>
                    {hits &&
                      (hits.length === 0 ? (
                        <p className="text-sm text-muted-foreground">
                          {t('settings.ai.knowledge.preview.none', 'Nothing would be retrieved.')}
                        </p>
                      ) : (
                        <ul className="space-y-2">
                          {hits.map((h, i) => (
                            <li
                              key={`${h.document_id}-${i}`}
                              className="rounded-md border p-3 text-sm"
                            >
                              <p className="font-medium">
                                {toDisplayText(h.document_title, 120)}
                                {h.section ? ` > ${toDisplayText(h.section, 120)}` : ''}
                              </p>
                              <p className="mt-1 whitespace-pre-wrap text-muted-foreground">
                                {toDisplayText(h.excerpt, 1000)}
                              </p>
                            </li>
                          ))}
                        </ul>
                      ))}
                  </section>
                )}
              </>
            )}
          </SheetBody>
          {canManage && src && (
            <SheetFooter className="flex-wrap">
              {hasPending && active && (
                <>
                  <Button onClick={() => setPending({ kind: 'approve' })}>
                    {t('settings.ai.knowledge.action.approve', 'Approve')}
                  </Button>
                  <Button variant="outline" onClick={() => setPending({ kind: 'reject' })}>
                    {t('settings.ai.knowledge.action.reject', 'Reject')}
                  </Button>
                </>
              )}
              {src.status !== 'disabled' && src.status !== 'rejected' && (
                <Button variant="outline" onClick={() => setPending({ kind: 'disable' })}>
                  {t('settings.ai.knowledge.action.disable', 'Disable')}
                </Button>
              )}
              <Button variant="destructive" onClick={() => setPending({ kind: 'deleteSource' })}>
                {t('settings.ai.knowledge.action.delete', 'Delete source')}
              </Button>
            </SheetFooter>
          )}
        </SheetContent>
      </Sheet>
      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        destructive={confirm.destructive}
        title={confirm.title}
        desc={confirm.desc}
        confirmText={confirm.label}
        handleConfirm={confirmPending}
      >
        {pending?.kind === 'reject' && (
          <div className="grid gap-2">
            <Label htmlFor="knowledge-reject-reason">
              {t('settings.ai.knowledge.reject.reason', 'Reason')}
            </Label>
            <Textarea
              id="knowledge-reject-reason"
              rows={3}
              value={reason}
              maxLength={500}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
        )}
      </ConfirmDialog>
    </>
  )
}
