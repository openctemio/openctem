package cirun

import (
	"net"
	"strings"
)

// sharedIssuerHosts are the issuer hosts of hosted CI services where anyone
// can run a pipeline: a rule that does not name owners or repositories
// would admit strangers there. A host matches with its subdomains, so
// "ghe.com" covers every GitHub data-residency tenant (example.ghe.com and
// its token.actions.example.ghe.com issuer). A self-managed GitLab with open
// sign-up has the same exposure; there the pending approval of new projects
// is what protects an all-projects configuration.
var sharedIssuerHosts = []string{
	"gitlab.com", "jihulab.com", "gitlab.cn", githubHost, "ghe.com",
	githubActionsIssuerHost, azureIssuerHost, circleCIIssuerHost, bitbucketAPIHost,
}

// Hosts of hosted CI issuers.
const (
	githubHost              = "github.com"
	githubActionsIssuerHost = "token.actions.githubusercontent.com"
	azureIssuerHost         = "vstoken.dev.azure.com"
	circleCIIssuerHost      = "oidc.circleci.com"
	bitbucketAPIHost        = "api.bitbucket.org"
)

// SharedIssuer reports whether issuer belongs to a hosted CI service shared
// by many customers (gitlab.com and its subdomains included), or has no
// host.
func SharedIssuer(issuer string) bool {
	h := IssuerHost(issuer)
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.TrimSuffix(h, ".")
	for _, s := range sharedIssuerHosts {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return h == ""
}
