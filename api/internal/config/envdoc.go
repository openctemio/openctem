package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Renderers for the files generated from env_registry.yaml (`make env-docs`,
// cmd/envdoc). TestEnvDocsUpToDate fails when a committed copy is stale.

// Generated file paths, relative to api/.
const (
	EnvExamplePath   = ".env.example"
	EnvReferencePath = "docs/configuration/environment-variables.md"
)

var componentTitles = []struct{ ID, Title, Intro string }{
	{"api", "API server", "Read by the API server at start-up (`server`). The server refuses to start when a variable under one of its prefixes is a likely misspelling of a listed name, or when a typed value does not parse; `server -check-config` runs the same checks without starting."},
	{"tool", "Administration tools", "Read by the command-line tools shipped with the server (`bootstrap-admin`, `rekey`, `openctem-signer`, ...), in addition to the database variables."},
	{"web", "Web console", "Read by the Next.js web console. `NEXT_PUBLIC_*` values are compiled into the browser bundle at build time: never put a secret in one."},
	{"gateway", "Gateway", "Read by the bundled Caddy gateway (`api/deploy/gateway`)."},
	{"compose", "Docker Compose stack", "Read by `api/deploy/docker-compose.yml` from its `.env` file."},
	{"allinone", "All-in-one image", "Read by the all-in-one image's supervisor."},
}

var mdLinkRE = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)

// plain turns a Markdown description into plain text for a comment.
func plain(s string) string {
	s = mdLinkRE.ReplaceAllString(s, "$1")
	return strings.ReplaceAll(s, "`", "")
}

func wrap(s string, width int, prefix string) []string {
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		if line != "" && len(prefix)+len(line)+1+len(w) > width {
			out = append(out, prefix+line)
			line = w
			continue
		}
		if line == "" {
			line = w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		out = append(out, prefix+line)
	}
	return out
}

// RenderEnvExample renders api/.env.example: the variables a local
// development checkout sets. Everything else keeps its default.
func RenderEnvExample(r *EnvRegistry) string {
	var b strings.Builder
	b.WriteString(`# OpenCTEM API: local development settings. Copy to .env.
#
# GENERATED from internal/config/env_registry.yaml by "make env-docs"; edit the
# registry, not this file. It lists only what a development checkout sets;
# every other variable keeps its default (full list with defaults:
# docs/configuration/environment-variables.md). Production installs start from
# deploy/.env.example instead.
#
# The keys below are the public development keys: the API refuses them unless
# APP_ENV=development.
`)
	group := ""
	for i := range r.Vars {
		v := &r.Vars[i]
		if v.Component != envComponentAPI || (v.Example == "" && v.Required != envRequiredYes) {
			continue
		}
		if v.Group != group {
			group = v.Group
			fmt.Fprintf(&b, "\n# --- %s %s\n", group, strings.Repeat("-", max(3, 74-len(group))))
		}
		for _, l := range wrap(plain(v.Description), 79, "# ") {
			b.WriteString(l + "\n")
		}
		val := v.Example
		if val == "" {
			val = v.Default
		}
		fmt.Fprintf(&b, "%s=%s\n", v.Name, val)
	}
	return b.String()
}

func mdCell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
}

// RenderEnvReference renders the environment variable reference page.
func RenderEnvReference(r *EnvRegistry) string {
	var b strings.Builder
	b.WriteString(`# Environment variable reference

<!-- GENERATED from api/internal/config/env_registry.yaml by "make env-docs". Do not edit. -->

Every environment variable OpenCTEM reads. **Default** is the value used when the
variable is unset or empty (durations in Go syntax: ` + "`30s`, `5m`, `24h`" + `; lists
comma-separated). **Required**: ` + "`yes`" + ` means it must be set; ` + "`production`" + ` means
production (` + "`APP_ENV`" + ` unset or ` + "`production`" + `) refuses to start without a valid value.
**Secret** values belong in a secret store, never in version control or logs.

Settings an administrator changes at run time (sign-up policy, plans, scan
approval, AI applications, ...) are not environment variables: they live in the
admin console and the organization settings.
`)
	for _, c := range componentTitles {
		fmt.Fprintf(&b, "\n## %s\n\n%s\n", c.Title, c.Intro)
		if c.ID == envComponentAPI {
			fmt.Fprintf(&b, "\nPrefixes the API owns: %s.\n", "`"+strings.Join(r.Prefixes, "`, `")+"`")
		}
		group := ""
		for i := range r.Vars {
			v := &r.Vars[i]
			if v.Component != c.ID {
				continue
			}
			if v.Group != group && c.ID == envComponentAPI {
				group = v.Group
				fmt.Fprintf(&b, "\n### %s\n\n| Variable | Type | Default | Required | Secret | Description |\n|---|---|---|---|---|---|\n", group)
			} else if group == "" {
				group = v.Group
				b.WriteString("\n| Variable | Type | Default | Required | Secret | Description |\n|---|---|---|---|---|---|\n")
			}
			typ := v.Type
			if v.Type == envTypeEnum {
				typ = strings.Join(v.Values, " \\| ")
			}
			def := "empty"
			if v.Default != "" {
				def = "`" + mdCell(v.Default) + "`"
			}
			secret := ""
			if v.Secret {
				secret = "yes"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n", v.Name, typ, def, v.Required, secret, mdCell(v.Description))
		}
	}
	b.WriteString("\n## Retired and removed names\n\nThe API refuses to start while one of these is set, and says what to do instead.\n\n| Variable | Instead |\n|---|---|\n")
	for _, x := range retiredEnv {
		instead := mdCell(x.Hint)
		if x.Hint == "" {
			instead = "rename it to `" + mdCell(x.New) + "`"
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", x.Old, instead)
	}
	for _, x := range removedEnv {
		fmt.Fprintf(&b, "| `%s` | %s |\n", x.Name, mdCell(x.Instead))
	}
	return b.String()
}
