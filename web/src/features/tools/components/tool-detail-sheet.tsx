'use client'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  type DetailMenuItem,
} from '@/features/shared'
import {
  ArrowUpCircle,
  Check,
  Clock,
  Copy,
  ExternalLink,
  FileOutput,
  Github,
  Hash,
  Layers,
  Power,
  PowerOff,
  Settings,
  Tag,
  Target,
  Terminal,
  Trash2,
  Zap,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { cn, sanitizeExternalUrl } from '@/lib/utils'
import { useState } from 'react'
import type { Tool } from '@/lib/api/tool-types'
import type { ToolCategory } from '@/lib/api/tool-category-types'
import { INSTALL_METHOD_DISPLAY_NAMES } from '@/lib/api/tool-types'
import { getCategoryNameById, getCategoryDisplayNameById } from '@/lib/api/tool-category-hooks'
import { CapabilityBadge } from '@/components/capability-badge'
import { ToolCategoryIcon, getCategoryBadgeColor } from './tool-category-icon'

interface ToolDetailSheetProps {
  tool: Tool | null
  categories?: ToolCategory[] // For looking up category name from category_id
  open: boolean
  onOpenChange: (open: boolean) => void
  onEdit?: (tool: Tool) => void
  onDelete?: (tool: Tool) => void
  onActivate?: (tool: Tool) => void
  onDeactivate?: (tool: Tool) => void
  onCheckUpdate?: (tool: Tool) => void
  /** When true, hides edit/delete/activate/deactivate actions (for platform tools) */
  readOnly?: boolean
}

function CommandBlock({ label, command }: { label: string; command: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await copyToClipboard(command)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <DetailField label={label} full>
      <span className="flex items-start gap-2">
        <code className="min-w-0 flex-1 rounded bg-muted/50 px-2 py-1.5 font-mono text-xs break-all">
          <span className="text-muted-foreground select-none">$ </span>
          {command}
        </code>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 shrink-0"
          aria-label={`Copy ${label.toLowerCase()} command`}
          onClick={handleCopy}
        >
          {copied ? (
            <Check className="h-3.5 w-3.5 text-success" />
          ) : (
            <Copy className="h-3.5 w-3.5" />
          )}
        </Button>
      </span>
    </DetailField>
  )
}

export function ToolDetailSheet({
  tool,
  categories,
  open,
  onOpenChange,
  onEdit,
  onDelete,
  onActivate,
  onDeactivate,
  onCheckUpdate,
  readOnly = false,
}: ToolDetailSheetProps) {
  if (!tool) return null

  // Look up category name from category_id
  const categoryName = getCategoryNameById(categories, tool.category_id)
  const categoryDisplayName = getCategoryDisplayNameById(categories, tool.category_id)

  const hasCommands = tool.install_cmd || tool.version_cmd || tool.update_cmd
  const canEdit = !readOnly && !tool.is_builtin && !!onEdit
  const canDelete = !readOnly && !tool.is_builtin && !!onDelete
  const toggle = readOnly
    ? null
    : tool.is_active
      ? onDeactivate && { label: 'Deactivate', icon: PowerOff, run: () => onDeactivate(tool) }
      : onActivate && { label: 'Activate', icon: Power, run: () => onActivate(tool) }

  const menu: DetailMenuItem[] = []
  if (tool.docs_url) {
    menu.push({
      label: 'Documentation',
      icon: ExternalLink,
      onSelect: () =>
        window.open(sanitizeExternalUrl(tool.docs_url!), '_blank', 'noopener,noreferrer'),
    })
  }
  if (tool.github_url) {
    menu.push({
      label: 'GitHub',
      icon: Github,
      onSelect: () =>
        window.open(sanitizeExternalUrl(tool.github_url!), '_blank', 'noopener,noreferrer'),
    })
  }
  if (canEdit && toggle) {
    menu.push({ label: toggle.label, icon: toggle.icon, onSelect: toggle.run })
  }
  menu.push({
    label: 'Copy ID',
    icon: Hash,
    onSelect: () => {
      copyToClipboard(tool.id)
      toast.success('Tool ID copied to clipboard')
    },
  })
  if (canDelete) {
    menu.push({
      label: 'Delete tool',
      icon: Trash2,
      destructive: true,
      separatorBefore: true,
      onSelect: () => onDelete!(tool),
    })
  }

  // One primary (update when one is waiting, else edit, else the on/off
  // switch) and one outline; everything else is in the menu.
  const update =
    !readOnly && tool.has_update && onCheckUpdate ? (
      <Button size="sm" onClick={() => onCheckUpdate(tool)}>
        <ArrowUpCircle className="h-4 w-4" />
        Update
      </Button>
    ) : null
  const edit = canEdit ? (
    <Button size="sm" variant={update ? 'outline' : 'default'} onClick={() => onEdit!(tool)}>
      <Settings className="h-4 w-4" />
      Edit
    </Button>
  ) : null
  const toggleButton =
    !canEdit && toggle ? (
      <Button size="sm" variant={update ? 'outline' : 'default'} onClick={toggle.run}>
        <toggle.icon className="h-4 w-4" />
        {toggle.label}
      </Button>
    ) : null
  const actions = [update, edit, toggleButton].filter(Boolean).slice(0, 2)

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      width="lg"
      header={
        <DetailHeader
          title={tool.display_name}
          badges={
            <>
              <Badge
                variant="outline"
                className={cn(
                  'text-xs',
                  tool.is_active && 'border-success/30 bg-success/10 text-success'
                )}
              >
                {tool.is_active ? 'Active' : 'Inactive'}
              </Badge>
              {tool.is_builtin && (
                <Badge variant="outline" className="text-xs">
                  Built-in
                </Badge>
              )}
              {tool.has_update && (
                <Badge
                  variant="outline"
                  className="gap-1 border-warning/40 bg-warning/10 text-xs text-warning"
                >
                  <ArrowUpCircle className="h-3 w-3" />
                  Update available
                </Badge>
              )}
            </>
          }
          meta={[
            <span key="name" className="font-mono">
              {tool.name}
            </span>,
            categoryDisplayName,
          ]}
          actions={actions.length > 0 ? <>{actions}</> : undefined}
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
    >
      <div className="space-y-5">
        {tool.has_update && tool.latest_version && (
          <DetailCallout
            tone="warning"
            icon={ArrowUpCircle}
            title={`Version ${tool.latest_version} is available`}
          >
            {tool.current_version
              ? `Installed: ${tool.current_version}.`
              : 'The tool is not installed yet.'}
          </DetailCallout>
        )}

        <DetailSections>
          {tool.description && (
            <DetailSection title="Description">
              <p className="text-sm leading-relaxed text-muted-foreground">{tool.description}</p>
            </DetailSection>
          )}

          <DetailSection title="Details" icon={Layers}>
            <DetailFieldGrid>
              <DetailField label="Category">
                <Badge
                  variant="outline"
                  className={cn('text-xs', getCategoryBadgeColor(categoryName))}
                >
                  <ToolCategoryIcon category={categoryName} className="me-1 h-3 w-3" />
                  {categoryDisplayName}
                </Badge>
              </DetailField>
              <DetailField label="Install method">
                {INSTALL_METHOD_DISPLAY_NAMES[tool.install_method]}
              </DetailField>
              <DetailField label="Version">
                {tool.current_version || 'Not installed'}
                {tool.has_update && tool.latest_version && (
                  <span className="text-warning"> ({tool.latest_version})</span>
                )}
              </DetailField>
              <DetailField label="Type">{tool.is_builtin ? 'Built-in' : 'Custom'}</DetailField>
            </DetailFieldGrid>
          </DetailSection>

          {hasCommands && (
            <DetailSection title="Commands" icon={Terminal}>
              <DetailFieldGrid>
                {tool.install_cmd && <CommandBlock label="Install" command={tool.install_cmd} />}
                {tool.version_cmd && (
                  <CommandBlock label="Version check" command={tool.version_cmd} />
                )}
                {tool.update_cmd && <CommandBlock label="Update" command={tool.update_cmd} />}
              </DetailFieldGrid>
            </DetailSection>
          )}

          {tool.capabilities && tool.capabilities.length > 0 && (
            <DetailSection title="Capabilities" icon={Zap} count={tool.capabilities.length}>
              <div className="flex flex-wrap gap-2">
                {tool.capabilities.map((cap) => (
                  <CapabilityBadge key={cap} name={cap} showIcon />
                ))}
              </div>
            </DetailSection>
          )}

          {tool.supported_targets && tool.supported_targets.length > 0 && (
            <DetailSection
              title="Supported targets"
              icon={Target}
              count={tool.supported_targets.length}
            >
              <div className="flex flex-wrap gap-1.5">
                {tool.supported_targets.map((target) => (
                  <Badge key={target} variant="secondary" className="text-xs font-normal">
                    {target}
                  </Badge>
                ))}
              </div>
            </DetailSection>
          )}

          {tool.output_formats && tool.output_formats.length > 0 && (
            <DetailSection
              title="Output formats"
              icon={FileOutput}
              count={tool.output_formats.length}
            >
              <div className="flex flex-wrap gap-1.5">
                {tool.output_formats.map((format) => (
                  <Badge key={format} variant="outline" className="text-xs font-normal">
                    {format}
                  </Badge>
                ))}
              </div>
            </DetailSection>
          )}

          {tool.tags && tool.tags.length > 0 && (
            <DetailSection title="Tags" icon={Tag} count={tool.tags.length}>
              <div className="flex flex-wrap gap-1.5">
                {tool.tags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="text-xs font-normal">
                    {tag}
                  </Badge>
                ))}
              </div>
            </DetailSection>
          )}

          <DetailSection title="Timeline" icon={Clock}>
            <DetailFieldGrid>
              <DetailField label="Created">
                {new Date(tool.created_at).toLocaleDateString(undefined, {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                })}
              </DetailField>
              <DetailField label="Updated">
                {new Date(tool.updated_at).toLocaleDateString(undefined, {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                })}
              </DetailField>
            </DetailFieldGrid>
          </DetailSection>
        </DetailSections>
      </div>
    </DetailSheet>
  )
}
