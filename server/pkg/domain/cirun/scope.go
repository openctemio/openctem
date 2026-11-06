package cirun

import (
	"strings"
)

// ScopePatterns are the repository scope patterns a trust configuration
// claims (docs/rfcs/RFC-054-scope-model.md, "Repository entries and CI
// trusts"), on the code host its tokens name: "host/owner/*" for each owner
// rule, "host/owner/repo" for an exact repository rule and "host/prefix/*"
// for a repository rule with a wildcard (the namespace before the first
// wildcard). With repository rules the owners only narrow them, so only the
// repositories count. None for a disabled trust, one that does not manage
// scope, or a provider whose tokens name the code host per run (Azure
// Pipelines, CircleCI, Jenkins) or name repositories by id (Bitbucket).
func ScopePatterns(c *TrustConfig) []string {
	if c == nil || !c.Enabled || !c.ManageScope {
		return nil
	}
	var host string
	switch c.Provider {
	case ProviderGitHub:
		host = GitHubHost(c.Issuer)
	case ProviderGitLab:
		host = IssuerHost(c.Issuer)
	default:
		return nil
	}
	if host == "" {
		return nil
	}
	var out []string
	add := func(p string) {
		p = strings.ToLower(p)
		for _, have := range out {
			if have == p {
				return
			}
		}
		out = append(out, p)
	}
	if len(c.Rules.Repositories) > 0 {
		for _, r := range c.Rules.Repositories {
			segs := strings.Split(strings.Trim(r, "/"), "/")
			literal := make([]string, 0, len(segs))
			wild := false
			for _, s := range segs {
				if strings.ContainsAny(s, "*?[") {
					wild = true
					break
				}
				literal = append(literal, s)
			}
			if len(literal) == 0 {
				continue // Validate refuses a wildcard owner
			}
			if wild {
				add(host + "/" + strings.Join(literal, "/") + "/*")
			} else {
				add(host + "/" + strings.Join(literal, "/"))
			}
		}
		return out
	}
	for _, o := range c.Rules.Owners {
		if o = strings.Trim(o, "/"); o != "" {
			add(host + "/" + o + "/*")
		}
	}
	return out
}
