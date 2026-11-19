'use client'

import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { SignalChip } from '@/components/ui/signal-chip'
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
  AlertTriangle,
  ArrowUpCircle,
  Check,
  Copy,
  ExternalLink,
  FileOutput,
  Github,
  Hash,
  Layers,
  PackagePlus,
  Power,
  PowerOff,
  Server,
  Settings,
  Tag,
  Target,
  Trash2,
  Zap,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { sanitizeExternalUrl } from '@/lib/utils'
import { formatRelative } from '@/lib/format-date'
import { useState } from 'react'
import type { Tool, ToolAvailabilityItem } from '@/lib/api/tool-types'
import type { ToolCategory } from '@/lib/api/tool-category-types'
import { INSTALL_METHOD_DISPLAY_NAMES } from '@/lib/api/tool-types'
import { getCategoryNameById, getCategoryDisplayNameById } from '@/lib/api/tool-category-hooks'
import { CapabilityBadge } from '@/components/capability-badge'
import { ToolCategoryIcon } from './tool-category-icon'
import { ToolSensorList, ToolStatusBadge, ToolTrustBadge } from './tool-availability'
import {
  sensorsLabel,
  toolDisplayName,
  toolUnavailableReason,
  versionsLabel,
} from '../lib/availability'

interface ToolDetailSheetProps {
  item: ToolAvailabilityItem
  categories?: ToolCategory[] // For looking up category name from category_id
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Custom tools only. */
  onEdit?: (tool: Tool) => void
  onDelete?: (tool: Tool) => void
  /** The organization's on/off switch; omitted without permission. */
  onToggleEnabled?: (item: ToolAvailabilityItem, enabled: boolean) => void
}

function CommandBlock({ label, command }: { label: string; command: string }) {
  const { t } = useTranslation()
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
          className="shrink-0"
          aria-label={t('scans.tools.detail.copyCommand', 'Copy the command: {label}', { label })}
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

/** How to get a tool onto a sensor: the catalog's install details. */
function AddToSensorSection({ tool }: { tool: Tool }) {
  const { t } = useTranslation()
  const hasCommands = tool.install_cmd || tool.version_cmd || tool.update_cmd
  return (
    <DetailSection
      title={t('scans.tools.detail.addTitle', 'How to add this tool to a sensor')}
      icon={PackagePlus}
    >
      <p className="mb-3 text-sm text-muted-foreground">
        {t(
          'scans.tools.detail.addBody',
          'Install it on the sensor host (or in the sensor image), then restart the sensor: it reports its tools when it starts, and the tool shows here with its version.'
        )}
      </p>
      <DetailFieldGrid>
        <DetailField label={t('scans.tools.detail.installMethod', 'Install method')}>
          {INSTALL_METHOD_DISPLAY_NAMES[tool.install_method] ?? tool.install_method}
        </DetailField>
        {tool.min_version && (
          <DetailField label={t('scans.tools.detail.minVersion', 'Minimum version')}>
            {tool.min_version}
          </DetailField>
        )}
        {hasCommands && (
          <>
            {tool.install_cmd && (
              <CommandBlock
                label={t('scans.tools.detail.cmdInstall', 'Install')}
                command={tool.install_cmd}
              />
            )}
            {tool.version_cmd && (
              <CommandBlock
                label={t('scans.tools.detail.cmdVersion', 'Version check')}
                command={tool.version_cmd}
              />
            )}
            {tool.update_cmd && (
              <CommandBlock
                label={t('scans.tools.detail.cmdUpdate', 'Update')}
                command={tool.update_cmd}
              />
            )}
          </>
        )}
      </DetailFieldGrid>
    </DetailSection>
  )
}

export function ToolDetailSheet({
  item,
  categories,
  open,
  onOpenChange,
  onEdit,
  onDelete,
  onToggleEnabled,
}: ToolDetailSheetProps) {
  const tool = item.tool
  const categoryName = getCategoryNameById(categories, tool?.category_id)
  const categoryDisplayName = tool ? getCategoryDisplayNameById(categories, tool.category_id) : ''
  const custom = !!tool && !tool.is_builtin
  const canEdit = custom && !!onEdit
  const canDelete = custom && !!onDelete
  const switchable = !!onToggleEnabled && !!tool && tool.is_active
  const { t } = useTranslation()
  const reason = toolUnavailableReason(item, t)
  const versions = versionsLabel(item)

  const toggle = switchable
    ? item.enabled
      ? {
          label: t('scans.tools.detail.disable', 'Disable'),
          icon: PowerOff,
          run: () => onToggleEnabled!(item, false),
        }
      : {
          label: t('scans.tools.detail.enable', 'Enable'),
          icon: Power,
          run: () => onToggleEnabled!(item, true),
        }
    : null

  const menu: DetailMenuItem[] = []
  if (tool?.docs_url) {
    menu.push({
      label: t('scans.tools.action.docs', 'Documentation'),
      icon: ExternalLink,
      onSelect: () =>
        window.open(sanitizeExternalUrl(tool.docs_url!), '_blank', 'noopener,noreferrer'),
    })
  }
  if (tool?.github_url) {
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
  if (tool) {
    menu.push({
      label: t('scans.tools.detail.copyId', 'Copy ID'),
      icon: Hash,
      onSelect: () => {
        copyToClipboard(tool.id)
        toast.success(t('scans.tools.detail.idCopied', 'Tool ID copied'))
      },
    })
  }
  if (canDelete) {
    menu.push({
      label: t('scans.tools.detail.delete', 'Delete tool'),
      icon: Trash2,
      destructive: true,
      separatorBefore: true,
      onSelect: () => onDelete!(tool!),
    })
  }

  // One primary (edit for a custom tool, else the on/off switch); the rest
  // is in the menu.
  const primary = canEdit ? (
    <Button size="sm" onClick={() => onEdit!(tool!)}>
      <Settings className="h-4 w-4" />
      {t('scans.tools.action.edit', 'Edit')}
    </Button>
  ) : toggle ? (
    <Button size="sm" variant={item.enabled ? 'outline' : 'default'} onClick={toggle.run}>
      <toggle.icon className="h-4 w-4" />
      {toggle.label}
    </Button>
  ) : null

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      width="lg"
      header={
        <DetailHeader
          title={toolDisplayName(item)}
          badges={
            <>
              <ToolStatusBadge item={item} />
              <ToolTrustBadge item={item} />
              {tool?.is_builtin && (
                <Badge variant="outline" className="text-xs">
                  {t('scans.tools.filter.builtin', 'Built-in')}
                </Badge>
              )}
              {custom && (
                <Badge variant="outline" className="text-xs">
                  {t('scans.tools.badge.custom', 'Custom')}
                </Badge>
              )}
              {item.update_available && (
                <SignalChip icon={ArrowUpCircle}>
                  {t('scans.tools.detail.updateAvailable', 'Update available')}
                </SignalChip>
              )}
            </>
          }
          meta={[
            <span key="name" className="font-mono">
              {item.name}
            </span>,
            categoryDisplayName,
          ].filter(Boolean)}
          actions={primary ?? undefined}
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
    >
      <div className="space-y-5">
        {reason && (
          <DetailCallout tone="warning" icon={AlertTriangle} title={reason}>
            {t(
              'scans.tools.detail.refusedBody',
              'Scans with this tool are refused until a sensor that may run it is online.'
            )}
          </DetailCallout>
        )}
        {!item.in_catalog && (
          <DetailCallout
            tone="info"
            icon={PackagePlus}
            title={t('scans.tools.detail.notInCatalogTitle', 'Not in the tool catalog')}
          >
            {t(
              'scans.tools.detail.notInCatalogBody',
              'A sensor reports this tool, but the catalog does not list it. Add it as a custom tool to scan with it.'
            )}
          </DetailCallout>
        )}

        <DetailSections>
          {tool?.description && (
            <DetailSection title={t('scans.tools.detail.description', 'Description')}>
              <p className="text-sm leading-relaxed text-muted-foreground">{tool.description}</p>
            </DetailSection>
          )}

          <DetailSection title={t('scans.tools.detail.onSensors', 'On your sensors')} icon={Server}>
            <DetailFieldGrid>
              <DetailField label={t('scans.tools.col.sensors', 'Sensors')}>
                {sensorsLabel(item, t)}
              </DetailField>
              <DetailField label={t('scans.tools.col.versions', 'Version(s)')}>
                {versions || '–'}
                {item.update_available && item.latest_version && (
                  <span className="text-warning">
                    {' '}
                    {t('scans.tools.detail.newestKnown', '(newest known {version})', {
                      version: item.latest_version,
                    })}
                  </span>
                )}
              </DetailField>
              {item.min_version && (
                <DetailField label={t('scans.tools.detail.minVersion', 'Minimum version')}>
                  {item.min_version}
                </DetailField>
              )}
              <DetailField label={t('scans.tools.col.lastReported', 'Last reported')}>
                {formatRelative(item.last_reported_at, '–')}
              </DetailField>
              {item.content.map((c) => (
                <DetailField
                  key={c.name}
                  label={t('scans.tools.detail.content', 'Content: {name}', { name: c.name })}
                >
                  <span className="tabular-nums">{c.versions.join(', ') || '–'}</span>
                </DetailField>
              ))}
            </DetailFieldGrid>
            <ToolSensorList item={item} className="mt-3" />
          </DetailSection>

          {tool && (
            <DetailSection title={t('scans.tools.detail.details', 'Details')} icon={Layers}>
              <DetailFieldGrid>
                <DetailField label={t('scans.tools.col.category', 'Category')}>
                  <Badge variant="outline" className="text-xs">
                    <ToolCategoryIcon category={categoryName} className="me-1 h-3 w-3" />
                    {categoryDisplayName}
                  </Badge>
                </DetailField>
                <DetailField label={t('scans.tools.filter.type', 'Type')}>
                  {tool.is_builtin
                    ? t('scans.tools.filter.builtin', 'Built-in')
                    : t('scans.tools.badge.custom', 'Custom')}
                </DetailField>
                <DetailField label={t('scans.tools.col.enabled', 'Enabled')}>
                  {item.enabled
                    ? t('scans.tools.detail.yes', 'Yes')
                    : t('scans.tools.detail.no', 'No')}
                </DetailField>
              </DetailFieldGrid>
            </DetailSection>
          )}

          {tool && <AddToSensorSection tool={tool} />}

          {tool && tool.capabilities && tool.capabilities.length > 0 && (
            <DetailSection
              title={t('scans.tools.detail.capabilities', 'Capabilities')}
              icon={Zap}
              count={tool.capabilities.length}
            >
              <div className="flex flex-wrap gap-2">
                {tool.capabilities.map((cap) => (
                  <CapabilityBadge key={cap} name={cap} showIcon />
                ))}
              </div>
            </DetailSection>
          )}

          {tool && tool.supported_targets && tool.supported_targets.length > 0 && (
            <DetailSection
              title={t('scans.tools.detail.targets', 'Supported targets')}
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

          {tool && tool.output_formats && tool.output_formats.length > 0 && (
            <DetailSection
              title={t('scans.tools.detail.outputs', 'Output formats')}
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

          {tool && tool.tags && tool.tags.length > 0 && (
            <DetailSection
              title={t('scans.tools.detail.tags', 'Tags')}
              icon={Tag}
              count={tool.tags.length}
            >
              <div className="flex flex-wrap gap-1.5">
                {tool.tags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="text-xs font-normal">
                    {tag}
                  </Badge>
                ))}
              </div>
            </DetailSection>
          )}
        </DetailSections>
      </div>
    </DetailSheet>
  )
}
