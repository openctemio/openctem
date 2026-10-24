'use client'

import { useState, useCallback } from 'react'
import { toast } from 'sonner'
import { Plus, FileText, ExternalLink, Calendar, User, Loader2, X, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { usePermissions } from '@/context/permission-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  useFindingEvidenceNotes,
  useAddFindingEvidence,
  useDeleteFindingEvidence,
  type FindingEvidenceNote,
} from '../../api/use-finding-evidence'
import { SafeExternalLink } from '@/components/safe-external-link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { confirmName } from '@/lib/confirm-name'
import { useTranslation } from '@/context/i18n-provider'

interface ManualEvidenceNotesSectionProps {
  findingId: string
}

function formatDate(dateString: string, locale: string): string {
  const d = new Date(dateString)
  return Number.isNaN(d.getTime())
    ? dateString
    : d.toLocaleDateString(locale, {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
}

/** Uploader display: prefer the resolved name, fall back to the UUID, then "Unknown". */
function uploaderLabel(
  note: FindingEvidenceNote,
  t: ReturnType<typeof useTranslation>['t']
): string {
  const name = note.uploaded_by_name?.trim()
  if (name) return name
  const id = note.uploaded_by?.trim()
  return id || t('findings.manualEvidence.unknown', 'Unknown')
}

function NoteCard({
  note,
  canWrite,
  onDelete,
  isDeleting,
}: {
  note: FindingEvidenceNote
  canWrite: boolean
  onDelete: (note: FindingEvidenceNote) => void
  isDeleting: boolean
}) {
  const { t, locale } = useTranslation()
  const hasUrl = !!note.url
  return (
    <div className="rounded-lg border p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="bg-muted flex h-8 w-8 shrink-0 items-center justify-center rounded">
          <FileText className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1 space-y-2">
          <p className="text-sm whitespace-pre-wrap break-words">{note.description}</p>
          {hasUrl && (
            <SafeExternalLink
              href={note.url}
              className="inline-flex items-center gap-1 text-sm text-primary hover:underline break-all"
            >
              {note.url}
              <ExternalLink className="h-3 w-3 shrink-0" />
            </SafeExternalLink>
          )}
          <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-xs">
            {note.type && (
              <Badge variant="outline" className="text-xs">
                {note.type}
              </Badge>
            )}
            <span className="flex items-center gap-1">
              <Calendar className="h-3 w-3" />
              {formatDate(note.created_at, locale)}
            </span>
            <span className="flex items-center gap-1">
              <User className="h-3 w-3" />
              {uploaderLabel(note, t)}
            </span>
          </div>
        </div>
        {canWrite && (
          <Button
            size="icon"
            variant="ghost"
            className="text-muted-foreground hover:text-destructive h-8 w-8 shrink-0"
            aria-label={t('findings.manualEvidence.deleteAria', 'Delete evidence note')}
            disabled={isDeleting}
            onClick={() => onDelete(note)}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  )
}

/**
 * ManualEvidenceNotesSection renders operator-authored evidence notes for a
 * finding and (with findings:write) an inline form to add more.
 * Backed by GET/POST /api/v1/findings/{id}/evidence{,/notes}.
 */
export function ManualEvidenceNotesSection({ findingId }: ManualEvidenceNotesSectionProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission('findings:write')

  const { data, mutate } = useFindingEvidenceNotes(findingId)
  const { trigger: addEvidence, isMutating } = useAddFindingEvidence(findingId)
  const { trigger: deleteEvidence, isMutating: isDeleting } = useDeleteFindingEvidence(findingId)

  const [showForm, setShowForm] = useState(false)
  const [description, setDescription] = useState('')
  const [type, setType] = useState('')
  const [url, setUrl] = useState('')
  const [noteToDelete, setNoteToDelete] = useState<FindingEvidenceNote | null>(null)

  const notes = data?.data ?? []

  const resetForm = useCallback(() => {
    setDescription('')
    setType('')
    setUrl('')
    setShowForm(false)
  }, [])

  const handleSubmit = useCallback(async () => {
    const trimmed = description.trim()
    if (!trimmed) {
      toast.error(t('findings.manualEvidence.descRequired', 'Description is required'))
      return
    }
    try {
      await addEvidence({
        description: trimmed,
        type: type.trim() || undefined,
        url: url.trim() || undefined,
      })
      toast.success(t('findings.manualEvidence.added', 'Evidence added'))
      resetForm()
      void mutate()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.manualEvidence.addFailed', 'Failed to add evidence'))
      )
    }
  }, [description, type, url, addEvidence, resetForm, mutate, t])

  const handleConfirmDelete = useCallback(async () => {
    if (!noteToDelete) return
    try {
      await deleteEvidence(noteToDelete.id)
      toast.success(t('findings.manualEvidence.deleted', 'Evidence deleted'))
      setNoteToDelete(null)
      void mutate()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('findings.manualEvidence.deleteFailed', 'Failed to delete evidence')
        )
      )
    }
  }, [noteToDelete, deleteEvidence, mutate, t])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-2 font-semibold">
          <FileText className="h-4 w-4" />
          {notes.length > 0
            ? t('findings.manualEvidence.notesCount', 'Notes ({count})', { count: notes.length })
            : t('findings.manualEvidence.notes', 'Notes')}
        </h3>
        {canWrite && !showForm && (
          <Button size="sm" variant="outline" onClick={() => setShowForm(true)}>
            <Plus className="me-2 h-4 w-4" />
            {t('findings.manualEvidence.addEvidence', 'Add Evidence')}
          </Button>
        )}
      </div>

      {canWrite && showForm && (
        <div className="space-y-3 rounded-lg border bg-muted/30 p-4">
          <div className="space-y-1.5">
            <Label htmlFor="evidence-description">
              {t('findings.manualEvidence.description', 'Description')}{' '}
              <span className="text-destructive">*</span>
            </Label>
            <Textarea
              id="evidence-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder={t(
                'findings.manualEvidence.descPlaceholder',
                'Describe the evidence (e.g. steps to reproduce, observed behaviour)…'
              )}
              rows={3}
              disabled={isMutating}
            />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="evidence-type">{t('findings.manualEvidence.type', 'Type')}</Label>
              <Input
                id="evidence-type"
                value={type}
                onChange={(e) => setType(e.target.value)}
                placeholder={t(
                  'findings.manualEvidence.typePlaceholder',
                  'e.g. log, screenshot, note'
                )}
                disabled={isMutating}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="evidence-url">{t('findings.manualEvidence.url', 'URL')}</Label>
              <Input
                id="evidence-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://…"
                disabled={isMutating}
              />
            </div>
          </div>
          <div className="flex items-center justify-end gap-2">
            <Button size="sm" variant="ghost" onClick={resetForm} disabled={isMutating}>
              <X className="me-1.5 h-3.5 w-3.5" />
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button size="sm" onClick={handleSubmit} disabled={isMutating || !description.trim()}>
              {isMutating ? (
                <Loader2 className="me-1.5 h-3.5 w-3.5 animate-spin" />
              ) : (
                <Plus className="me-1.5 h-3.5 w-3.5" />
              )}
              {t('findings.manualEvidence.addEvidence', 'Add Evidence')}
            </Button>
          </div>
        </div>
      )}

      {notes.length > 0 ? (
        <div className="space-y-3">
          {notes.map((note) => (
            <NoteCard
              key={note.id}
              note={note}
              canWrite={canWrite}
              onDelete={setNoteToDelete}
              isDeleting={isDeleting && noteToDelete?.id === note.id}
            />
          ))}
        </div>
      ) : (
        !showForm && (
          <p className="text-muted-foreground text-sm">
            {t('findings.manualEvidence.empty', 'No notes added yet.')}
            {!canWrite &&
              ` ${t('findings.manualEvidence.noPermission', 'You do not have permission to add evidence.')}`}
          </p>
        )
      )}

      <ConfirmDialog
        open={!!noteToDelete}
        onOpenChange={(open) => {
          if (!open && !isDeleting) setNoteToDelete(null)
        }}
        destructive
        title={t('confirm.evidenceNote.deleteTitle', 'Delete this evidence note?')}
        desc={t(
          'confirm.evidenceNote.deleteDesc',
          "The note and its link are permanently removed from the finding's evidence. The finding itself is not changed."
        )}
        typeToConfirm={
          noteToDelete ? confirmName(noteToDelete.description, noteToDelete.id) : undefined
        }
        confirmText={
          isDeleting ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.deleting', 'Deleting…')}
            </>
          ) : (
            t('confirm.evidenceNote.deleteButton', 'Delete note')
          )
        }
        isLoading={isDeleting}
        handleConfirm={() => handleConfirmDelete()}
      />
    </div>
  )
}
