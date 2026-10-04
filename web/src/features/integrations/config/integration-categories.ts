import {
  GitBranch,
  MessageSquare,
  Shield,
  ShieldCheck,
  TicketCheck,
  type LucideIcon,
} from 'lucide-react'

export interface IntegrationCategoryCard {
  id: string
  title: string
  description: string
  icon: LucideIcon
  href: string
  /**
   * 'Soon' when the target page is a ComingSoonPage. Pinned both ways by
   * src/config/__tests__/sidebar-no-scaffolds.test.ts: a placeholder page needs
   * the badge, and a badge needs a placeholder page.
   */
  badge?: 'Soon'
}

/**
 * The category cards on the Integrations overview: navigation to the pages
 * that own each connect flow. Kept outside the page file so the badge test can
 * read it (an App Router page may only export its component).
 */
export const INTEGRATION_CATEGORIES: IntegrationCategoryCard[] = [
  // Same order and names as Settings › Integrations in the settings rail.
  // API keys are not an integration; they live in Settings › Access.
  {
    id: 'scm',
    title: 'Source control',
    description: 'Connect GitHub, GitLab, Bitbucket, or Azure DevOps',
    icon: GitBranch,
    href: '/settings/integrations/scm',
  },
  {
    id: 'security',
    title: 'Vulnerability scanners',
    description: 'Import Nessus and Tenable scan exports',
    icon: ShieldCheck,
    href: '/settings/integrations/scanners',
  },
  {
    id: 'ticketing',
    title: 'Ticketing',
    description: 'Connect Jira, ServiceNow, or Linear',
    icon: TicketCheck,
    href: '/settings/integrations/ticketing',
  },
  {
    id: 'notifications',
    title: 'Notification channels',
    description: 'Slack, Teams, Telegram, and webhook alerts',
    icon: MessageSquare,
    href: '/settings/integrations/notifications',
  },
  {
    id: 'siem',
    title: 'SIEM',
    description: 'Forward security events to Splunk',
    icon: Shield,
    href: '/settings/integrations/siem',
  },
]
