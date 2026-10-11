package config

import (
	_ "embed"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// The environment variable registry (env_registry.yaml) is the one list of
// every variable the API and its tools read. Startup validation, the
// generated api/.env.example and the generated reference page come from it,
// and TestEnvRegistryMatchesCode keeps it equal to what the code reads.

//go:embed env_registry.yaml
var envRegistryYAML []byte

// Registry field values used in code.
const (
	envComponentAPI = "api"
	envTypeEnum     = "enum"
	envRequiredYes  = "yes"
)

// EnvVar is one registered environment variable.
type EnvVar struct {
	Name        string   `yaml:"name"`
	Component   string   `yaml:"component"`
	Group       string   `yaml:"group"`
	Type        string   `yaml:"type"`
	Values      []string `yaml:"values"`
	Default     string   `yaml:"default"`
	Required    string   `yaml:"required"`
	Secret      bool     `yaml:"secret"`
	Example     string   `yaml:"example"`
	Description string   `yaml:"description"`
}

// EnvRegistry is the parsed env_registry.yaml.
type EnvRegistry struct {
	Prefixes []string `yaml:"prefixes"`
	Vars     []EnvVar `yaml:"vars"`
	byName   map[string]*EnvVar
}

// Lookup returns the registered variable called name.
func (r *EnvRegistry) Lookup(name string) (*EnvVar, bool) {
	v, ok := r.byName[name]
	return v, ok
}

var loadEnvRegistry = sync.OnceValues(func() (*EnvRegistry, error) {
	return parseEnvRegistry(envRegistryYAML)
})

// Registry returns the embedded environment variable registry. The embedded
// file is checked by the package tests, so an error here is a build defect.
func Registry() *EnvRegistry {
	r, err := loadEnvRegistry()
	if err != nil {
		panic(err)
	}
	return r
}

var envNameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func parseEnvRegistry(b []byte) (*EnvRegistry, error) {
	var r EnvRegistry
	if err := yaml.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("env registry: %w", err)
	}
	r.byName = make(map[string]*EnvVar, len(r.Vars))
	for i := range r.Vars {
		v := &r.Vars[i]
		if !envNameRE.MatchString(v.Name) {
			return nil, fmt.Errorf("env registry: bad name %q", v.Name)
		}
		if _, dup := r.byName[v.Name]; dup {
			return nil, fmt.Errorf("env registry: %s listed twice", v.Name)
		}
		switch v.Component {
		case "api", "tool", "web", "gateway", "compose", "allinone":
		default:
			return nil, fmt.Errorf("env registry: %s: unknown component %q", v.Name, v.Component)
		}
		switch v.Type {
		case "string", "int", "bool", "duration", "float", "list", "url", "path":
		case envTypeEnum:
			if len(v.Values) == 0 {
				return nil, fmt.Errorf("env registry: %s: enum without values", v.Name)
			}
		default:
			return nil, fmt.Errorf("env registry: %s: unknown type %q", v.Name, v.Type)
		}
		switch v.Required {
		case "", envRequiredYes, "production":
		default:
			return nil, fmt.Errorf("env registry: %s: required must be yes or production", v.Name)
		}
		if v.Group == "" || v.Description == "" {
			return nil, fmt.Errorf("env registry: %s needs a group and a description", v.Name)
		}
		if v.Secret && v.Example != "" && v.Component != envComponentAPI {
			return nil, fmt.Errorf("env registry: %s: only api secrets may carry a development example", v.Name)
		}
		r.byName[v.Name] = v
	}
	return &r, nil
}

// kubernetesServiceLinkRE matches the variables Kubernetes injects for every
// Service in the namespace (enableServiceLinks), e.g. REDIS_SERVICE_HOST or
// REDIS_PORT_6379_TCP_ADDR. They are not configuration.
var kubernetesServiceLinkRE = regexp.MustCompile(`_SERVICE_(HOST|PORT(_[A-Z0-9_]+)?)$|_PORT_[0-9]+_(TCP|UDP|SCTP)(_(PROTO|PORT|ADDR))?$`)

func retiredOrRemoved(name string) bool {
	for _, r := range retiredEnv {
		if r.Old == name {
			return true
		}
	}
	for _, r := range removedEnv {
		if r.Name == name {
			return true
		}
	}
	return false
}

// checkEnvironment looks at every set variable under a prefix the API owns.
//
//   - Not in the registry and close to a registered name (edit distance at
//     most 3): refused with a "did you mean" hint. This is the dangerous case,
//     a typo such as REDIS_PASWORD or AUTH_COOKIE_SECUR that would otherwise be
//     ignored and leave a default in place.
//   - Not in the registry and not close to any name: returned as a warning
//     (logged at startup, printed by -check-config). Such a name usually
//     belongs to something else in the same environment, and refusing to start
//     over it would turn a harmless variable into an outage.
//   - A set api variable whose value does not parse as its type: refused. The
//     getters would otherwise replace it with the default without a word.
//
// Messages name variables, never values.
func checkEnvironment(r *EnvRegistry, environ []string) (warnings []string, err error) {
	var typos, invalid []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		v, known := r.Lookup(name)
		if !known {
			if retiredOrRemoved(name) || kubernetesServiceLinkRE.MatchString(name) || !hasOwnedPrefix(r, name) {
				continue
			}
			if s := r.suggest(name); s != "" {
				typos = append(typos, name+" (did you mean "+s+"?)")
			} else {
				warnings = append(warnings, name+" is set but not read by the API")
			}
			continue
		}
		if v.Component != envComponentAPI || strings.TrimSpace(value) == "" {
			continue
		}
		if msg := v.checkValue(value); msg != "" {
			invalid = append(invalid, name+" "+msg)
		}
	}
	slices.Sort(warnings)
	var parts []string
	if len(typos) > 0 {
		slices.Sort(typos)
		parts = append(parts, "unknown environment variables (not read by the API; fix the name or unset it): "+strings.Join(typos, ", "))
	}
	if len(invalid) > 0 {
		slices.Sort(invalid)
		parts = append(parts, "invalid environment variable values: "+strings.Join(invalid, ", "))
	}
	if len(parts) > 0 {
		return warnings, fmt.Errorf("%s", strings.Join(parts, "; "))
	}
	return warnings, nil
}

// SetAPIVariables returns the sorted names of the registered api variables
// set (non-empty) in environ. Names only: values may be secrets.
func SetAPIVariables(environ []string) []string {
	r := Registry()
	var out []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if v, ok := r.Lookup(name); ok && v.Component == envComponentAPI && strings.TrimSpace(value) != "" {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func hasOwnedPrefix(r *EnvRegistry, name string) bool {
	for _, p := range r.Prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// checkValue reports why value is not a valid v, or "".
func (v *EnvVar) checkValue(value string) string {
	value = strings.TrimSpace(value)
	switch v.Type {
	case "int":
		// A Kubernetes service link (REDIS_PORT=tcp://10.0.0.1:6379) is not
		// the operator's setting; the default applies as before.
		if strings.HasSuffix(v.Name, "_PORT") && strings.HasPrefix(value, "tcp://") {
			return ""
		}
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return "is not an integer"
		}
	case "bool":
		if _, err := strconv.ParseBool(value); err != nil {
			return "is not true or false"
		}
	case "duration":
		if _, err := time.ParseDuration(value); err != nil {
			return "is not a duration (for example 30s, 15m, 24h)"
		}
	case "float":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return "is not a number"
		}
	case envTypeEnum:
		if !slices.ContainsFunc(v.Values, func(s string) bool { return strings.EqualFold(s, value) }) {
			return "must be one of " + strings.Join(v.Values, ", ")
		}
	}
	return ""
}

// suggest returns the registered name closest to name (edit distance at most
// 3), or "".
func (r *EnvRegistry) suggest(name string) string {
	best, bestD := "", 4
	for i := range r.Vars {
		if d := editDistance(name, r.Vars[i].Name); d < bestD {
			best, bestD = r.Vars[i].Name, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
