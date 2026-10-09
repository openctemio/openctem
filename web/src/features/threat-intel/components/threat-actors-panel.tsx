'use client'

/**
 * Threat Actors management tab.
 *
 * Backed by /api/v1/threat-actors (list/create/get/delete — no update endpoint,
 * so there is no edit action). Read gated by threat_intel:read, create/delete by
 * threat_intel:write. Type filter lives in the URL (?actor_type=) so a filtered
 * view is linkable.
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  Plus,
  Eye,
  Trash2,
  Users,
  Loader2,
  ExternalLink,
  AlertCircle,
  RefreshCw,
  Copy,
} from 'lucide-react'
import { toast } from 'sonner'

import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  type DetailMenuItem,
} from '@/features/shared'
import { copyToClipboard } from '@/lib/clipboard'
import { cn, sanitizeExternalUrl } from '@/lib/utils'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useUrlFilter } from '@/hooks/use-url-param'
import {
  useThreatActors,
  useCreateThreatActor,
  useDeleteThreatActor,
  ACTOR_TYPES,
  ACTOR_TYPE_LABELS,
  type ThreatActor,
  type ActorType,
  type CreateThreatActorInput,
} from '../api/use-threat-actors-api'

const ALL = 'all'

function formatDate(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString()
}

/** "financial_gain" → "Financial gain" (motivation is stored as a slug). */
function humanize(raw?: string): string {
  const s = (raw ?? '').replace(/_/g, ' ').trim()
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''
}

/** Split a comma/newline separated field into a trimmed, non-empty string list. */
function splitList(raw: string): string[] {
  return raw
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean)
}

export function ThreatActorsPanel() {
  const { can } = usePermissions()
  const canRead = can(Permission.ThreatIntelRead)

  const { data, error, isLoading, mutate } = useThreatActors(
    canRead ? { per_page: 200 } : undefined
  )
  const [typeFilter, setTypeFilter] = useUrlFilter('actor_type', ALL)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ThreatActor | null>(null)

  const actors = useMemo(() => {
    const rows = data?.data ?? []
    if (typeFilter === ALL) return rows
    return rows.filter((a) => a.actor_type === typeFilter)
  }, [data, typeFilter])

  const selected = useMemo(
    () => actors.find((a) => a.id === selectedId) ?? null,
    [actors, selectedId]
  )

  const columns = useMemo<ColumnDef<ThreatActor>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
        cell: ({ row }) => {
          const a = row.original
          return (
            <div className="min-w-0">
              <div className="font-medium truncate">{a.name}</div>
              {(a.aliases ?? []).length > 0 && (
                <div className="text-xs text-muted-foreground truncate">
                  {(a.aliases ?? []).join(', ')}
                </div>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'actor_type',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Type" />,
        cell: ({ row }) => (
          <Badge variant="secondary">
            {ACTOR_TYPE_LABELS[row.original.actor_type] ?? row.original.actor_type}
          </Badge>
        ),
      },
      {
        accessorKey: 'motivation',
        header: 'Motivation',
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {humanize(row.original.motivation) || '—'}
          </span>
        ),
      },
      {
        id: 'ttps',
        header: 'TTPs',
        cell: ({ row }) => {
          const n = row.original.ttps?.length ?? 0
          return n > 0 ? (
            <Badge variant="outline">{n}</Badge>
          ) : (
            <span className="text-muted-foreground">—</span>
          )
        },
      },
      {
        accessorKey: 'mitre_group_id',
        header: 'MITRE group',
        cell: ({ row }) =>
          row.original.mitre_group_id ? (
            <span className="font-mono text-xs">{row.original.mitre_group_id}</span>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      {
        accessorKey: 'updated_at',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Updated" />,
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatDate(row.original.updated_at)}
          </span>
        ),
      },
      {
        id: 'actions',
        cell: ({ row }) => (
          <DataTableRowActions
            actions={[
              { label: 'View details', icon: Eye, onClick: () => setSelectedId(row.original.id) },
              {
                label: 'Delete',
                icon: Trash2,
                destructive: true,
                separatorBefore: true,
                permission: Permission.ThreatIntelWrite,
                onClick: () => setDeleteTarget(row.original),
              },
            ]}
          />
        ),
      },
    ],
    []
  )

  if (!canRead) {
    return (
      <EmptyState
        icon={Users}
        title="No access to threat actors"
        description="You need the View Threat Intel permission to see the threat actor catalogue."
      />
    )
  }

  // The type filter and "Add actor" live in the table toolbar: this panel is a
  // tab of the Threat intelligence page, whose header is the page's only one.
  const typeSelect = (
    <Select value={typeFilter} onValueChange={setTypeFilter}>
      <SelectTrigger className="h-9 w-40" aria-label="Filter by actor type">
        <SelectValue placeholder="All types" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>All types</SelectItem>
        {ACTOR_TYPES.map((t) => (
          <SelectItem key={t} value={t}>
            {ACTOR_TYPE_LABELS[t]}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )

  return (
    <div className="space-y-4">
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : error ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Failed to load threat actors</AlertTitle>
          <AlertDescription>
            <p>{getErrorMessage(error, 'Please try again.')}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={() => mutate()}>
              <RefreshCw className="me-2 h-4 w-4" />
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      ) : (
        <DataTable
          columns={columns}
          data={actors}
          searchPlaceholder="Search actors…"
          emptyMessage="No threat actors"
          emptyDescription="Add an adversary group to start tracking it."
          onRowClick={(row) => setSelectedId(row.id)}
          toolbarEnd={
            <>
              {typeSelect}
              <Can permission={Permission.ThreatIntelWrite} mode="disable">
                <Button size="sm" className="h-9" onClick={() => setCreateOpen(true)}>
                  <Plus className="h-4 w-4 sm:me-2" />
                  <span className="hidden sm:inline">Add actor</span>
                </Button>
              </Can>
            </>
          }
        />
      )}

      <ThreatActorDetailSheet
        actor={selected}
        open={!!selected}
        onOpenChange={(open) => !open && setSelectedId(null)}
        onDelete={(a) => {
          setSelectedId(null)
          setDeleteTarget(a)
        }}
      />

      <CreateThreatActorDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => mutate()}
      />

      <DeleteThreatActorConfirm
        actor={deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        onDeleted={() => {
          setDeleteTarget(null)
          mutate()
        }}
      />
    </div>
  )
}

// ── Detail sheet ────────────────────────────────────────────────────────────
export function ThreatActorDetailSheet({
  actor,
  open,
  onOpenChange,
  onDelete,
}: {
  actor: ThreatActor | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onDelete: (actor: ThreatActor) => void
}) {
  const { can } = usePermissions()
  const canWrite = can(Permission.ThreatIntelWrite)
  if (!actor) return null

  // The API sends null for an empty list (ttps on every actor created
  // without TTPs); reading .length on it crashed the page when the drawer
  // opened.
  const aliases = actor.aliases ?? []
  const ttps = actor.ttps ?? []
  const references = actor.external_references ?? []
  const industries = actor.target_industries ?? []
  const regions = actor.target_regions ?? []
  const tags = actor.tags ?? []

  const menu: DetailMenuItem[] = []
  if (actor.mitre_group_id) {
    menu.push({
      label: 'Copy MITRE ID',
      icon: Copy,
      onSelect: () => {
        copyToClipboard(actor.mitre_group_id!)
        toast.success('MITRE ID copied to clipboard')
      },
    })
  }
  if (canWrite) {
    menu.push({
      label: 'Delete threat actor',
      icon: Trash2,
      destructive: true,
      separatorBefore: menu.length > 0,
      onSelect: () => onDelete(actor),
    })
  }

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      header={
        <DetailHeader
          title={actor.name}
          badges={
            <>
              <Badge variant="outline" className="text-xs">
                {ACTOR_TYPE_LABELS[actor.actor_type] ?? actor.actor_type}
              </Badge>
              <Badge
                variant="outline"
                className={cn(
                  'text-xs',
                  actor.is_active && 'border-success/30 bg-success/10 text-success'
                )}
              >
                {actor.is_active ? 'Active' : 'Inactive'}
              </Badge>
              {actor.mitre_group_id && (
                <Badge variant="outline" className="font-mono text-xs">
                  {actor.mitre_group_id}
                </Badge>
              )}
            </>
          }
          meta={[
            actor.country_of_origin,
            actor.motivation ? humanize(actor.motivation) : null,
            `Updated ${formatDate(actor.updated_at)}`,
          ]}
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
    >
      <DetailSections>
        {actor.description && (
          <DetailSection title="Description">
            <p className="text-sm text-muted-foreground">{actor.description}</p>
          </DetailSection>
        )}

        <DetailSection title="Profile">
          <DetailFieldGrid>
            {aliases.length > 0 && (
              <DetailField label="Aliases" full>
                {aliases.join(', ')}
              </DetailField>
            )}
            {actor.motivation && (
              <DetailField label="Motivation">{humanize(actor.motivation)}</DetailField>
            )}
            {actor.sophistication && (
              <DetailField label="Sophistication">{actor.sophistication}</DetailField>
            )}
            {actor.country_of_origin && (
              <DetailField label="Country of origin">{actor.country_of_origin}</DetailField>
            )}
            {industries.length > 0 && (
              <DetailField label="Target industries" full>
                {industries.join(', ')}
              </DetailField>
            )}
            {regions.length > 0 && (
              <DetailField label="Target regions" full>
                {regions.join(', ')}
              </DetailField>
            )}
            <DetailField label="Updated">{formatDate(actor.updated_at)}</DetailField>
          </DetailFieldGrid>
        </DetailSection>

        {ttps.length > 0 && (
          <DetailSection title="TTPs" icon={Users} count={ttps.length}>
            <ul className="divide-y rounded-lg border">
              {ttps.map((t, i) => (
                <li key={i} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                  {t.technique_id && (
                    <span className="font-mono text-xs text-muted-foreground">
                      {t.technique_id}
                    </span>
                  )}
                  <span className="min-w-0 break-words">{t.technique_name || t.tactic}</span>
                  {t.tactic && t.technique_name && (
                    <Badge variant="outline" className="text-xs">
                      {t.tactic}
                    </Badge>
                  )}
                </li>
              ))}
            </ul>
          </DetailSection>
        )}

        {references.length > 0 && (
          <DetailSection title="References" icon={ExternalLink} count={references.length}>
            <ul className="space-y-1.5">
              {references.map((ref, i) => (
                <li key={i}>
                  <a
                    href={sanitizeExternalUrl(ref.url)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm break-all text-primary hover:underline"
                  >
                    {ref.source || ref.url}
                    <ExternalLink className="h-3 w-3 shrink-0" />
                  </a>
                </li>
              ))}
            </ul>
          </DetailSection>
        )}

        {tags.length > 0 && (
          <DetailSection title="Tags" count={tags.length}>
            <div className="flex flex-wrap gap-1">
              {tags.map((tag) => (
                <Badge key={tag} variant="outline">
                  {tag}
                </Badge>
              ))}
            </div>
          </DetailSection>
        )}
      </DetailSections>
    </DetailSheet>
  )
}

// ── Create dialog ───────────────────────────────────────────────────────────
function CreateThreatActorDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: () => void
}) {
  const { trigger } = useCreateThreatActor()
  const [submitting, setSubmitting] = useState(false)
  const [name, setName] = useState('')
  const [actorType, setActorType] = useState<ActorType>('unknown')
  const [aliases, setAliases] = useState('')
  const [description, setDescription] = useState('')
  const [motivation, setMotivation] = useState('')
  const [country, setCountry] = useState('')
  const [mitreId, setMitreId] = useState('')
  const [tags, setTags] = useState('')

  const reset = () => {
    setName('')
    setActorType('unknown')
    setAliases('')
    setDescription('')
    setMotivation('')
    setCountry('')
    setMitreId('')
    setTags('')
  }

  const handleSubmit = async () => {
    if (!name.trim()) {
      toast.error('Name is required')
      return
    }
    const payload: CreateThreatActorInput = {
      name: name.trim(),
      actor_type: actorType,
      aliases: splitList(aliases),
      description: description.trim(),
      motivation: motivation.trim(),
      country_of_origin: country.trim(),
      mitre_group_id: mitreId.trim(),
      tags: splitList(tags),
    }
    setSubmitting(true)
    try {
      await trigger(payload)
      toast.success(`Threat actor "${payload.name}" added`)
      reset()
      onOpenChange(false)
      onCreated()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to add threat actor'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add threat actor</DialogTitle>
          <DialogDescription>Track a new adversary group for this tenant.</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="ta-name">Name *</Label>
              <Input
                id="ta-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. APT29"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ta-type">Type</Label>
              <Select value={actorType} onValueChange={(v) => setActorType(v as ActorType)}>
                <SelectTrigger id="ta-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ACTOR_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {ACTOR_TYPE_LABELS[t]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="ta-aliases">Aliases</Label>
              <Input
                id="ta-aliases"
                value={aliases}
                onChange={(e) => setAliases(e.target.value)}
                placeholder="Comma-separated, e.g. Cozy Bear, The Dukes"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ta-desc">Description</Label>
              <Textarea
                id="ta-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="ta-motivation">Motivation</Label>
                <Input
                  id="ta-motivation"
                  value={motivation}
                  onChange={(e) => setMotivation(e.target.value)}
                  placeholder="e.g. Espionage"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ta-country">Country of origin</Label>
                {/* Stored as a 3-letter code; the API rejects anything longer. */}
                <Input
                  id="ta-country"
                  value={country}
                  maxLength={3}
                  placeholder="ISO code, e.g. RU"
                  onChange={(e) => setCountry(e.target.value.toUpperCase())}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="ta-mitre">MITRE group ID</Label>
                <Input
                  id="ta-mitre"
                  value={mitreId}
                  onChange={(e) => setMitreId(e.target.value)}
                  placeholder="e.g. G0016"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ta-tags">Tags</Label>
                <Input
                  id="ta-tags"
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                  placeholder="Comma-separated"
                />
              </div>
            </div>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={submitting}>
            {submitting && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            Add actor
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Delete confirm ──────────────────────────────────────────────────────────
function DeleteThreatActorConfirm({
  actor,
  onOpenChange,
  onDeleted,
}: {
  actor: ThreatActor | null
  onOpenChange: (open: boolean) => void
  onDeleted: () => void
}) {
  const { trigger } = useDeleteThreatActor(actor?.id ?? '')
  const [deleting, setDeleting] = useState(false)

  const handleConfirm = async () => {
    if (!actor) return
    setDeleting(true)
    try {
      await trigger()
      toast.success(`Threat actor "${actor.name}" deleted`)
      onDeleted()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to delete threat actor'))
    } finally {
      setDeleting(false)
    }
  }

  return (
    <ConfirmDialog
      open={!!actor}
      onOpenChange={onOpenChange}
      title="Delete threat actor?"
      desc={
        actor
          ? `"${actor.name}" will be removed from this tenant's catalogue. This cannot be undone.`
          : ''
      }
      confirmText={deleting ? 'Deleting...' : 'Delete'}
      destructive
      handleConfirm={handleConfirm}
    />
  )
}
