import { Fragment } from 'react'
import { LEGAL_DOCS, type LegalDoc, type LegalValues } from '@/lib/legal'
import { TextLink } from '@/components/ui/text-link'
import { TEXT_LINK_CLASS } from '@/components/ui/text-link-class'
import { safeInternalHref } from '@/lib/safe-href'
import type { LegalSection } from './components/legal-document'
import { LegalMail, LegalWeb } from './components/legal-links'

/**
 * The built-in legal templates: Terms of Service, Acceptable Use Policy,
 * Privacy Policy, Data Processing Addendum and the subprocessor list. They are
 * a starting point reviewed with counsel and completed through the LEGAL_*
 * settings; what only the company can provide (legal name, address, governing
 * law) shows as a marked placeholder until it is set.
 */

const P = ({ children }: { children: React.ReactNode }) => <p>{children}</p>

const SECURITY_TXT = '/.well-known/security.txt'

/**
 * Prose with references to the other legal pages: "[the title](/path)" marks
 * a link, named by the page's title. Only the legal pages and security.txt
 * can be linked (a constant list, never data); any other mark stays text.
 * A paragraph stays one text, as the documents are written.
 */
function Linked({ children }: { children: string }) {
  const parts = children.split(/(\[[^\]]+\]\([^)]+\))/)
  return (
    <>
      {parts.map((part, i) => {
        const m = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(part)
        if (!m) return <Fragment key={i}>{part}</Fragment>
        const [, text, path] = m
        if (path === SECURITY_TXT)
          // A file, not a page: a plain link, no client-side navigation.
          return (
            <a key={i} href={safeInternalHref(SECURITY_TXT)} className={TEXT_LINK_CLASS.inline}>
              {text}
            </a>
          )
        const doc = LEGAL_DOCS.find((d) => d.path === path)
        if (!doc) return <Fragment key={i}>{text}</Fragment>
        return (
          <TextLink key={i} href={safeInternalHref(doc.path)} variant="inline">
            {doc.title}
          </TextLink>
        )
      })}
    </>
  )
}

function terms(v: LegalValues): LegalSection[] {
  return [
    {
      heading: 'Who we are',
      body: (
        <P>
          {v.service} (<LegalWeb url={v.website} />) is provided by {v.organization}, {v.address}.
          These terms govern your use of the service. By creating an account or signing in you
          accept them for yourself and, where you act for an organization, for that organization.
        </P>
      ),
    },
    {
      heading: 'Your account',
      body: (
        <P>
          Keep your sign-in details and second factor secure, and tell us at{' '}
          <LegalMail to={v.securityEmail} /> if you suspect someone else has used your account.
          Organization owners decide who joins their organization and what each member may see and
          do.
        </P>
      ),
    },
    {
      heading: 'Acceptable use',
      body: (
        <P>
          <Linked>
            {
              'Your use of the service must follow the [Acceptable Use Policy](/acceptable-use). In short: scan, test or monitor only what you own or are authorized to assess. We may suspend accounts or organizations that break it.'
            }
          </Linked>
        </P>
      ),
    },
    {
      heading: 'Plans and limits',
      body: (
        <P>
          Each organization is on a plan with limits (members, assets, sensors and others). Lowering
          a limit never deletes your data; new additions over the limit are refused until usage is
          under it again.
        </P>
      ),
    },
    {
      heading: 'Your data',
      body: (
        <P>
          <Linked>
            {
              'You keep ownership of the data you bring. We process it to provide the service, as described in the [Privacy Policy](/privacy) and, for organizations, the [Data Processing Addendum](/dpa). You can export your data and ask for its deletion.'
            }
          </Linked>
        </P>
      ),
    },
    {
      heading: 'Availability and changes',
      body: (
        <P>
          We work to keep the service available and secure but do not guarantee that it is free of
          interruptions. Documentation lives at <LegalWeb url={v.docsUrl} />. We may change these
          terms and will announce material changes before they take effect.
        </P>
      ),
    },
    {
      heading: 'Liability',
      body: (
        <P>
          To the extent the law allows, the service is provided as is, and our liability is limited
          to the amount you paid for it in the twelve months before the claim.
        </P>
      ),
    },
    {
      heading: 'Governing law and contact',
      body: (
        <P>
          These terms are governed by {v.jurisdiction}. Questions: <LegalMail to={v.contactEmail} />
          .
        </P>
      ),
    },
  ]
}

function acceptableUse(v: LegalValues): LegalSection[] {
  return [
    {
      heading: 'Authorized targets only',
      body: (
        <P>
          Scan, test, discover or monitor only systems, domains, networks, code and accounts that
          you own or have written permission to assess. Platform scanning is available only for
          domains your organization has verified.
        </P>
      ),
    },
    {
      heading: 'Not allowed',
      body: (
        <ul className="list-disc space-y-1 ps-5">
          <li>Attacking, disrupting or gaining unauthorized access to any system or data.</li>
          <li>
            Denial of service, or testing that degrades a system you are not authorized to test.
          </li>
          <li>
            Getting around plan limits, rate limits, sign-up checks or other security controls.
          </li>
          <li>
            Probing or attacking the {v.service} platform itself outside a coordinated disclosure.
          </li>
          <li>Using the service to store or send malware, spam, or unlawful content.</li>
          <li>Sharing accounts, or creating accounts or organizations to evade a suspension.</li>
        </ul>
      ),
    },
    {
      heading: 'Reporting a vulnerability',
      body: (
        <P>
          Found a security issue in {v.service}? Write to <LegalMail to={v.securityEmail} />{' '}
          <Linked>
            {
              '([security.txt](/.well-known/security.txt)). Give us reasonable time to fix it before disclosing it.'
            }
          </Linked>
        </P>
      ),
    },
    {
      heading: 'Enforcement',
      body: (
        <P>
          We may suspend or remove accounts, organizations or scans that break this policy, and
          report unlawful activity to the authorities. Questions: <LegalMail to={v.contactEmail} />.
        </P>
      ),
    },
  ]
}

function privacy(v: LegalValues): LegalSection[] {
  return [
    {
      heading: 'Who is responsible',
      body: (
        <P>
          {v.organization}, {v.address}, is responsible for the personal data processed to run{' '}
          {v.service}. Contact: <LegalMail to={v.contactEmail} />.{' '}
          <Linked>
            {
              'For the data organizations bring to the service we act as their processor under the [Data Processing Addendum](/dpa).'
            }
          </Linked>
        </P>
      ),
    },
    {
      heading: 'What we collect',
      body: (
        <ul className="list-disc space-y-1 ps-5">
          <li>Account data: your name, email address, and sign-in and second-factor settings.</li>
          <li>
            Organization data an organization brings: assets, findings, scan results and the people
            assigned to them.
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
        <P>
          To provide and secure the service, to keep the audit trail organizations rely on, to
          prevent abuse, and to contact you about your account. We do not sell personal data.
        </P>
      ),
    },
    {
      heading: 'Sharing',
      body: (
        <P>
          <Linked>
            {
              'Data stays within your organization. We share it only with the subprocessors that host and operate the service for us ([Subprocessors](/subprocessors)), under contract, or when the law requires it.'
            }
          </Linked>
        </P>
      ),
    },
    {
      heading: 'How long we keep it',
      body: (
        <P>
          For as long as your account or organization exists. A deleted organization is kept for a
          14-day grace period, during which it can be exported, and then removed. Audit records may
          be kept longer where the law requires.
        </P>
      ),
    },
    {
      heading: 'Your rights',
      body: (
        <P>
          You can ask to see, correct, export or delete your personal data, and object to its use,
          by writing to <LegalMail to={v.contactEmail} />. You may also complain to your data
          protection authority.
        </P>
      ),
    },
    {
      heading: 'Changes',
      body: <P>We will announce material changes to this policy before they take effect.</P>,
    },
  ]
}

function dpa(v: LegalValues): LegalSection[] {
  return [
    {
      heading: 'Parties and scope',
      body: (
        <P>
          This addendum is between the customer organization (the controller) and {v.organization},{' '}
          {v.address}{' '}
          <Linked>
            {
              '(the processor), and forms part of the [Terms of Service](/terms). It covers the personal data the customer brings to'
            }
          </Linked>{' '}
          {v.service}.
        </P>
      ),
    },
    {
      heading: 'Processing',
      body: (
        <ul className="list-disc space-y-1 ps-5">
          <li>Subject matter: providing the {v.service} exposure management service.</li>
          <li>Duration: the term of the customer agreement, plus the deletion grace period.</li>
          <li>
            Data subjects: the customer&apos;s users, and people named in its assets and findings.
          </li>
          <li>Data: names, email addresses, account and audit records, and asset metadata.</li>
          <li>
            Instructions: we process customer data only on the customer&apos;s documented
            instructions.
          </li>
        </ul>
      ),
    },
    {
      heading: 'Security',
      body: (
        <P>
          We keep each organization&apos;s data isolated, encrypt credentials at rest and data in
          transit, enforce least-privilege access and second factors for administrators, and keep an
          audit trail. Our staff are bound by confidentiality.
        </P>
      ),
    },
    {
      heading: 'Subprocessors',
      body: (
        <P>
          <Linked>
            {
              'The customer authorizes the subprocessors listed in [Subprocessors](/subprocessors). We announce a new subprocessor before it starts processing customer data; the customer may object.'
            }
          </Linked>
        </P>
      ),
    },
    {
      heading: 'Incidents, assistance and audits',
      body: (
        <P>
          We notify the customer without undue delay after becoming aware of a personal data breach,
          help it answer data subject requests and assessments, and make available the information
          needed to demonstrate compliance. Security contact: <LegalMail to={v.securityEmail} />.
        </P>
      ),
    },
    {
      heading: 'End of processing',
      body: (
        <P>
          When the agreement ends, the customer can export its data during the grace period; we then
          delete it unless the law requires us to keep it.
        </P>
      ),
    },
    {
      heading: 'Governing law',
      body: <P>This addendum is governed by {v.jurisdiction}.</P>,
    },
  ]
}

function subprocessors(v: LegalValues): LegalSection[] {
  const rows: [string, string, string][] = [
    ['[Hosting provider: to be confirmed]', 'Infrastructure and data storage', '[Region]'],
    ['[Email delivery provider: to be confirmed]', 'Transactional email', '[Region]'],
  ]
  return [
    {
      heading: 'Who processes customer data for us',
      body: (
        <div className="overflow-x-auto">
          <table className="w-full text-start text-dense">
            {/* The sentence that introduces the list is the table's caption. */}
            <caption className="caption-top pb-2 text-start text-body/6">
              {v.organization} uses these subprocessors to provide {v.service}. We announce changes
              before they take effect. Questions: <LegalMail to={v.contactEmail} />.
            </caption>
            <thead>
              <tr className="border-b">
                <th className="py-2 pe-4 text-start font-medium text-foreground">Subprocessor</th>
                <th className="py-2 pe-4 text-start font-medium text-foreground">Purpose</th>
                <th className="py-2 text-start font-medium text-foreground">Location</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(([name, purpose, where]) => (
                <tr key={name} className="border-b">
                  <td className="py-2 pe-4">{name}</td>
                  <td className="py-2 pe-4">{purpose}</td>
                  <td className="py-2">{where}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ),
    },
  ]
}

const BUILDERS: Record<LegalDoc, (v: LegalValues) => LegalSection[]> = {
  terms,
  'acceptable-use': acceptableUse,
  privacy,
  dpa,
  subprocessors,
}

export function legalSections(doc: LegalDoc, v: LegalValues): LegalSection[] {
  return BUILDERS[doc](v)
}
