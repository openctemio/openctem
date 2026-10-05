import { redirect } from 'next/navigation'

// Domain verification for attack-surface management lives on each seed in
// Scoping > Boundaries > Seeds (research/22 P0-10). Domains for SSO sign-in
// stay with the platform administrator (admin console).
export default function VerifiedDomainsPage() {
  redirect('/scope-config?tab=seeds')
}
