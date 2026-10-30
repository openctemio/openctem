'use client'

import {
  Code,
  Package,
  Globe,
  Key,
  Server,
  Container,
  Search,
  Eye,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ToolCategory } from '@/lib/api/tool-types'

interface ToolCategoryIconProps {
  category: string // Accept any string to support custom categories
  className?: string
}

// Icons for builtin categories
const categoryIcons: Record<string, LucideIcon> = {
  sast: Code,
  sca: Package,
  dast: Globe,
  secrets: Key,
  iac: Server,
  container: Container,
  recon: Search,
  osint: Eye,
}

export const CATEGORY_LABELS: Record<ToolCategory, string> = {
  sast: 'SAST',
  sca: 'SCA',
  dast: 'DAST',
  secrets: 'Secrets',
  iac: 'IaC',
  container: 'Container',
  recon: 'Recon',
  osint: 'OSINT',
}

export const CATEGORY_DESCRIPTIONS: Record<ToolCategory, string> = {
  sast: 'Static Application Security Testing',
  sca: 'Software Composition Analysis',
  dast: 'Dynamic Application Security Testing',
  secrets: 'Secret Detection',
  iac: 'Infrastructure as Code',
  container: 'Container Security',
  recon: 'Reconnaissance',
  osint: 'Open Source Intelligence',
}

export function ToolCategoryIcon({ category, className }: ToolCategoryIconProps) {
  const Icon = categoryIcons[category] || Code
  return <Icon className={cn('text-muted-foreground', className)} />
}
