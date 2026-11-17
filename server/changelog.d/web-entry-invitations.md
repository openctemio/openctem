### Changed: invitation pages in the entry frame

- The invitation page (`/invitations`) and the ownership invitations page (`/ownership-invitations`) sit in the entry frame: the brand, one card, the legal links and the language menu. Each state of an invitation (loading, link not usable, declined, joined with two-factor still to set up, expired or already accepted, open) has one title, the organization as one row with the expiry chip when three days or fewer are left, and one teal primary action. A refused accept or open reads as one banner in the card, with the same texts.
- Ownership invitations use the wide entry column; My account keeps its card.
- The account space hub (`/welcome`) keeps its header and sign-out; its sections (verify, invitations, your company, create an organization, your account) are entry cards with their own headings.
- The GitHub App setup page has one page title and announces the outcome (an alert when GitHub or the API refused). The sensor activation page uses the type scale.
- Requests, redirects, cookies, tokens, error texts and confirmations are unchanged.
- Docs: web/docs/ui-style-contract.md ("Entry pages")
