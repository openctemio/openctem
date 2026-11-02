'use client'

import { useState } from 'react'
import { BookOpen, Plus } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { useGroups } from '@/features/access-control/api/use-groups'
import { TeamPicker } from '@/features/organization/components/team-picker'
import { EmptyState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { Permission, usePermissions } from '@/lib/permissions'
import { toDisplayText } from '@/lib/untrusted-text'

import {
  createKnowledgeSource,
  useAIKnowledgeSources,
  type KnowledgeDataClass,
  type KnowledgeVisibility,
} from '../api/use-ai-knowledge'
import { AIKnowledgeDrawer } from './ai-knowledge-drawer'
import { SourceStatusPill, dataClassText, formatBytes, visibilityText } from './ai-knowledge-shared'

function CreateDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: (id: string) => Promise<void>
}) {
  const { t } = useTranslation()
  const { groups, isLoading: teamsLoading } = useGroups(undefined, open)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [visibility, setVisibility] = useState<KnowledgeVisibility>('organization')
  const [teamIds, setTeamIds] = useState<string[]>([])
  const [dataClass, setDataClass] = useState<KnowledgeDataClass>('internal')
  const [busy, setBusy] = useState(false)

  const valid = name.trim() !== '' && (visibility === 'organization' || teamIds.length > 0)

  const submit = async () => {
    setBusy(true)
    try {
      const created = await createKnowledgeSource({
        name: name.trim(),
        description: description.trim(),
        visibility,
        data_class: dataClass,
        team_ids: visibility === 'teams' ? teamIds : [],
      })
      toast.success(
        t('settings.ai.knowledge.toast.created', 'Knowledge source added, waiting for approval')
      )
      setName('')
      setDescription('')
      setVisibility('organization')
      setTeamIds([])
      setDataClass('internal')
      onOpenChange(false)
      await onCreated(created.id)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (busy ? undefined : onOpenChange(o))}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {t('settings.ai.knowledge.createTitle', 'Add knowledge source')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'settings.ai.knowledge.createDescription',
              'A source groups documents. It starts pending: another person approves it before any AI agent reads it.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="knowledge-name">{t('settings.ai.knowledge.field.name', 'Name')}</Label>
            <Input
              id="knowledge-name"
              value={name}
              maxLength={120}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="knowledge-description">
              {t('settings.ai.knowledge.field.description', 'Description (optional)')}
            </Label>
            <Textarea
              id="knowledge-description"
              rows={2}
              value={description}
              maxLength={500}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label id="knowledge-visibility">
              {t('settings.ai.knowledge.col.visibility', 'Visibility')}
            </Label>
            <RadioGroup
              aria-labelledby="knowledge-visibility"
              value={visibility}
              onValueChange={(v) => setVisibility(v as KnowledgeVisibility)}
            >
              <div className="flex items-center gap-2">
                <RadioGroupItem id="knowledge-vis-org" value="organization" />
                <Label htmlFor="knowledge-vis-org">
                  {t('settings.ai.knowledge.visibility.organization', 'Organization')}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem id="knowledge-vis-teams" value="teams" />
                <Label htmlFor="knowledge-vis-teams">
                  {t('settings.ai.knowledge.visibility.teams', 'Teams')}
                </Label>
              </div>
            </RadioGroup>
            {visibility === 'teams' && (
              <>
                <Label id="knowledge-teams">
                  {t('settings.ai.knowledge.field.teams', 'Teams that can use it')}
                </Label>
                <TeamPicker
                  teams={groups}
                  selected={teamIds}
                  onChange={setTeamIds}
                  loading={teamsLoading}
                  labelledBy="knowledge-teams"
                />
              </>
            )}
          </div>
          <div className="grid gap-2">
            <Label>{t('settings.ai.knowledge.col.dataClass', 'Data class')}</Label>
            <Select value={dataClass} onValueChange={(v) => setDataClass(v as KnowledgeDataClass)}>
              <SelectTrigger aria-label={t('settings.ai.knowledge.col.dataClass', 'Data class')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="internal">
                  {t('settings.ai.knowledge.class.internal', 'Internal')}
                </SelectItem>
                <SelectItem value="restricted">
                  {t('settings.ai.knowledge.class.restricted', 'Restricted')}
                </SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {t(
                'settings.ai.knowledge.field.classHelp',
                'Restricted text is masked strictly and only reaches AI agents with a restricted ceiling.'
              )}
            </p>
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'settings.ai.knowledge.field.fixedNote',
              'Visibility, data class and teams cannot be changed later.'
            )}
          </p>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button disabled={!valid || busy} onClick={submit}>
            {t('settings.ai.knowledge.create', 'Add source')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Settings > AI > Knowledge sources: the runbooks, conventions and
 * architecture notes AI agents may cite (API docs:
 * architecture/ai-knowledge.md). Listing needs `ai_knowledge:read` (the page
 * mounts this only then); every change needs `ai_knowledge:manage`. The API
 * stays the authority: this only hides what would be refused.
 */
export function AIKnowledgeSection() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.AIKnowledgeRead)
  const canManage = can(Permission.AIKnowledgeManage)
  const sources = useAIKnowledgeSources(canRead)
  const [createOpen, setCreateOpen] = useState(false)
  const [openId, setOpenId] = useState<string | null>(null)

  if (!canRead) return null
  const rows = sources.data ?? []

  return (
    <Card id="ai-knowledge">
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <BookOpen className="h-4 w-4" aria-hidden />
            {t('settings.ai.knowledge.title', 'Knowledge sources')}
          </CardTitle>
          <CardDescription>
            {t(
              'settings.ai.knowledge.description',
              'Runbooks, conventions and architecture notes your AI agents may cite. Nothing reaches an AI agent until another person approves it.'
            )}
          </CardDescription>
        </div>
        {canManage && (
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="me-1 h-4 w-4" aria-hidden />
            {t('settings.ai.knowledge.addButton', 'Add source')}
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {sources.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : sources.error ? (
          <p className="text-sm text-destructive">{getErrorMessage(sources.error)}</p>
        ) : rows.length === 0 ? (
          <EmptyState
            icon={BookOpen}
            title={t('settings.ai.knowledge.empty.title', 'No knowledge sources yet')}
            description={t(
              'settings.ai.knowledge.empty.description',
              'Upload runbooks, naming conventions and architecture notes. Owners, criticality and SLAs come from your assets, so do not upload them.'
            )}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('settings.ai.knowledge.col.name', 'Name')}</TableHead>
                <TableHead>{t('settings.ai.knowledge.col.visibility', 'Visibility')}</TableHead>
                <TableHead>{t('settings.ai.knowledge.col.dataClass', 'Data class')}</TableHead>
                <TableHead>{t('settings.ai.knowledge.col.status', 'Status')}</TableHead>
                <TableHead>{t('settings.ai.knowledge.col.documents', 'Documents')}</TableHead>
                <TableHead>{t('settings.ai.knowledge.col.size', 'Size')}</TableHead>
                <TableHead>{t('settings.ai.knowledge.col.updated', 'Updated')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((s) => (
                <TableRow
                  key={s.id}
                  data-testid="ai-knowledge-row"
                  className="cursor-pointer"
                  onClick={() => setOpenId(s.id)}
                >
                  <TableCell>
                    <button
                      type="button"
                      className="text-start font-medium hover:underline"
                      onClick={(e) => {
                        e.stopPropagation()
                        setOpenId(s.id)
                      }}
                    >
                      {toDisplayText(s.name, 80)}
                    </button>
                    {s.description && (
                      <p className="text-sm text-muted-foreground">
                        {toDisplayText(s.description, 120)}
                      </p>
                    )}
                  </TableCell>
                  <TableCell>{visibilityText(t, s)}</TableCell>
                  <TableCell>{dataClassText(t, s.data_class)}</TableCell>
                  <TableCell>
                    <SourceStatusPill status={s.status} pendingDocuments={s.pending_documents} />
                  </TableCell>
                  <TableCell>{s.documents}</TableCell>
                  <TableCell>{formatBytes(s.bytes)}</TableCell>
                  <TableCell>{formatDateSafe(s.updated_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      {canManage && (
        <CreateDialog
          open={createOpen}
          onOpenChange={setCreateOpen}
          onCreated={async (id) => {
            await sources.mutate()
            setOpenId(id)
          }}
        />
      )}
      <AIKnowledgeDrawer
        sourceId={openId}
        canManage={canManage}
        onClose={() => setOpenId(null)}
        onChanged={() => sources.mutate()}
      />
    </Card>
  )
}
