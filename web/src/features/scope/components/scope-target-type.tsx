'use client'

/**
 * The scope target types as one picker and one icon map, shared by the Scope
 * page (targets and exclusions) and the scope entry dialog.
 */

import {
  Box,
  Cloud,
  Code,
  Database,
  Folder,
  GitBranch,
  Globe,
  Link,
  Mail,
  Server,
  Shield,
} from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const iconClass = 'h-4 w-4'

export const SCOPE_TARGET_TYPE_ICON: Record<string, React.ReactNode> = {
  domain: <Globe className={iconClass} />,
  subdomain: <Globe className={iconClass} />,
  ip_address: <Server className={iconClass} />,
  ip_range: <Server className={iconClass} />,
  cidr: <Server className={iconClass} />,
  url: <Link className={iconClass} />,
  certificate: <Shield className={iconClass} />,
  api: <Code className={iconClass} />,
  website: <Globe className={iconClass} />,
  mobile_app: <Box className={iconClass} />,
  cloud_account: <Cloud className={iconClass} />,
  cloud_resource: <Cloud className={iconClass} />,
  database: <Database className={iconClass} />,
  container: <Box className={iconClass} />,
  host: <Server className={iconClass} />,
  network: <Link className={iconClass} />,
  project: <GitBranch className={iconClass} />,
  repository: <GitBranch className={iconClass} />,
  path: <Folder className={iconClass} />,
  email_domain: <Mail className={iconClass} />,
}

export const SCOPE_TARGET_TYPE_GROUPS: { label: string; types: string[] }[] = [
  {
    label: 'Network & External',
    types: ['domain', 'subdomain', 'ip_address', 'ip_range', 'certificate'],
  },
  { label: 'Applications', types: ['api', 'website', 'mobile_app'] },
  { label: 'Cloud', types: ['cloud_account', 'cloud_resource'] },
  { label: 'Infrastructure', types: ['database', 'container', 'host', 'network'] },
  { label: 'Code & CI/CD', types: ['repository'] },
  { label: 'Other', types: ['path', 'email_domain'] },
]

/** "cloud_account" -> "Cloud account"; "ip_address" -> "IP address". */
export function scopeTargetTypeLabel(type: string): string {
  const special: Record<string, string> = {
    ip_address: 'IP address',
    ip_range: 'IP range',
    cidr: 'CIDR',
    url: 'URL',
    api: 'API',
  }
  if (special[type]) return special[type]
  const s = type.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** Types a member may request (one name or one address, RFC-054 §6.1). */
export const REQUESTABLE_TARGET_TYPES = ['domain', 'subdomain', 'ip_address']

interface ScopeTargetTypeSelectProps {
  value: string
  onValueChange: (v: string) => void
  disabled?: boolean
  /** Only these types (default: all). */
  only?: string[]
  /** Adds an "All types" item with value "all" (filters). */
  withAll?: boolean
  className?: string
  'aria-label'?: string
  id?: string
}

export function ScopeTargetTypeSelect({
  value,
  onValueChange,
  disabled,
  only,
  withAll,
  className,
  id,
  'aria-label': ariaLabel,
}: ScopeTargetTypeSelectProps) {
  const groups = SCOPE_TARGET_TYPE_GROUPS.map((g) => ({
    ...g,
    types: only ? g.types.filter((t) => only.includes(t)) : g.types,
  })).filter((g) => g.types.length > 0)
  return (
    <Select value={value} onValueChange={onValueChange} disabled={disabled}>
      <SelectTrigger className={className} aria-label={ariaLabel} id={id}>
        <SelectValue placeholder="Type" />
      </SelectTrigger>
      <SelectContent className="max-h-80">
        {withAll && <SelectItem value="all">All types</SelectItem>}
        {groups.map((group) => (
          <div key={group.label}>
            <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">
              {group.label}
            </div>
            {group.types.map((type) => (
              <SelectItem key={type} value={type}>
                <div className="flex items-center gap-2">
                  {SCOPE_TARGET_TYPE_ICON[type]}
                  {scopeTargetTypeLabel(type)}
                </div>
              </SelectItem>
            ))}
          </div>
        ))}
      </SelectContent>
    </Select>
  )
}
