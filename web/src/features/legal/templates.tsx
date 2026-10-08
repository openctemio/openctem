import type { LegalValues } from '@/lib/legal'
import type { LegalSection } from './components/legal-document'

/**
 * The built-in terms and privacy templates. They are a starting point the
 * operator reviews with their counsel and completes through the LEGAL_*
 * settings; an unset value shows as a bracketed placeholder.
 */

export function termsSections(v: LegalValues): LegalSection[] {
  return [
    {
      heading: 'Who we are',
      body: (
        <p>
          This service is provided by {v.organization} ({v.address}). These terms govern your use of
          it. By creating an account or signing in, you agree to them on behalf of yourself and,
          where you act for an organization, that organization.
        </p>
      ),
    },
    {
      heading: 'Your account',
      body: (
        <p>
          Keep your sign-in details and second factor secure and tell us at {v.contactEmail} if you
          suspect someone else has used your account. Organization owners decide who joins their
          organization and what each member may see and do.
        </p>
      ),
    },
    {
      heading: 'Acceptable use',
      body: (
        <>
          <p>
            Scan, test or monitor only systems you own or are authorized to assess. Do not use the
            service to attack, disrupt or gain unauthorized access to any system, to infringe the
            rights of others, or to get around plan limits or security controls.
          </p>
          <p>We may suspend accounts or organizations that break these rules.</p>
        </>
      ),
    },
    {
      heading: 'Plans and limits',
      body: (
        <p>
          Each organization is on a plan with limits (members, assets, sensors and others). Lowering
          a limit never deletes your data; new additions over the limit are refused until usage is
          under it again.
        </p>
      ),
    },
    {
      heading: 'Your data',
      body: (
        <p>
          You keep ownership of the data you bring to the service. We process it to provide the
          service, as described in the privacy policy. You can export your data and ask for its
          deletion.
        </p>
      ),
    },
    {
      heading: 'Availability and changes',
      body: (
        <p>
          We work to keep the service available and secure but do not guarantee that it is free of
          interruptions. We may change these terms; we will announce material changes before they
          take effect.
        </p>
      ),
    },
    {
      heading: 'Liability',
      body: (
        <p>
          To the extent the law allows, the service is provided as is, and our liability is limited
          to the amount you paid for it in the twelve months before the claim.
        </p>
      ),
    },
    {
      heading: 'Governing law and contact',
      body: (
        <p>
          These terms are governed by {v.jurisdiction}. Questions: {v.contactEmail}.
        </p>
      ),
    },
  ]
}

export function privacySections(v: LegalValues): LegalSection[] {
  return [
    {
      heading: 'Who is responsible',
      body: (
        <p>
          {v.organization} ({v.address}) is responsible for the personal data processed to run this
          service. Contact: {v.contactEmail}.
        </p>
      ),
    },
    {
      heading: 'What we collect',
      body: (
        <ul className="list-disc space-y-1 ps-5">
          <li>Account data: your name, email address, and sign-in and second-factor settings.</li>
          <li>
            Organization data your organization brings: assets, findings, scan results and the
            people assigned to them.
          </li>
          <li>
            Security and audit records: sign-ins, sessions, IP addresses and the actions taken in
            the service.
          </li>
        </ul>
      ),
    },
    {
      heading: 'Why we use it',
      body: (
        <p>
          To provide and secure the service, to keep the audit trail organizations rely on, to
          prevent abuse, and to contact you about your account. We do not sell personal data.
        </p>
      ),
    },
    {
      heading: 'Sharing',
      body: (
        <p>
          Data stays within your organization. We share it only with the providers that host and
          operate the service for us, under contract, or when the law requires it.
        </p>
      ),
    },
    {
      heading: 'How long we keep it',
      body: (
        <p>
          For as long as your account or organization exists. A deleted organization is kept for a
          grace period, during which it can be exported, and then removed. Audit records may be kept
          longer where the law requires.
        </p>
      ),
    },
    {
      heading: 'Your rights',
      body: (
        <p>
          You can ask to see, correct, export or delete your personal data, and object to its use,
          by writing to {v.contactEmail}. You may also complain to your data protection authority.
        </p>
      ),
    },
    {
      heading: 'Changes',
      body: <p>We will announce material changes to this policy before they take effect.</p>,
    },
  ]
}
