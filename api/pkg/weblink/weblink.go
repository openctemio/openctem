// Package weblink builds the console links the platform sends out (in-app
// notifications, e-mails, chat and webhook deliveries, pull request
// comments, ticket fields, AI agent tool results).
//
// Every such link names the organization it belongs to in the "org" query
// parameter (the organization ID). A person who belongs to several
// organizations can open the link while another one is selected: the console
// reads the parameter and, when the person is a member of that organization,
// switches to it through the normal organization switch (the API checks the
// membership) before it loads the page. The parameter grants nothing: a
// person who is not a member gets the same "not found" as without it.
//
// The organization ID is used, not the slug: it never changes (a renamed
// organization keeps working links) and every sender already has it.
package weblink

import (
	"net/url"
	"strings"
)

// OrgParam is the query parameter that names the organization of a link.
const OrgParam = "org"

// WithOrg returns link (a relative "/path?query#fragment" or an absolute URL)
// with org=<orgID> in its query, replacing any org value it had. An empty
// link, an empty orgID, or a link that does not parse comes back unchanged.
func WithOrg(link, orgID string) string {
	orgID = strings.TrimSpace(orgID)
	if link == "" || orgID == "" {
		return link
	}
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	q := u.Query()
	q.Set(OrgParam, orgID)
	u.RawQuery = q.Encode()
	return u.String()
}

// Absolute joins a console-relative link ("/findings/1") to the console's
// base URL. An absolute link, a protocol-relative one ("//host"), an empty
// link, or an empty base comes back unchanged.
func Absolute(base, link string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" || !strings.HasPrefix(link, "/") || strings.HasPrefix(link, "//") {
		return link
	}
	return base + link
}

// Console returns the absolute console link to path for the organization:
// Absolute(base, WithOrg(path, orgID)).
func Console(base, path, orgID string) string {
	return Absolute(base, WithOrg(path, orgID))
}
