// Package contentpkg is the content package format: the manifest
// (package.yaml), its JSON schema and its validation.
//
// Design: api/docs/rfcs/RFC-099-content-packages.md.
package contentpkg

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

// APIVersion is the manifest version this package reads.
const APIVersion = "openctem.io/package/v1"

// MaxManifestBytes bounds package.yaml.
const MaxManifestBytes = 64 << 10

// MaxArtifactBytes bounds an artifact.
const MaxArtifactBytes = 512 << 20

//go:embed schema/package.v1.schema.json
var schemaJSON []byte

// SchemaJSON is the JSON schema of the manifest (for publishers' tooling).
func SchemaJSON() []byte { return append([]byte(nil), schemaJSON...) }

// Type is what a package is.
type Type string

// Package types.
const (
	TypeRules           Type = "rules"
	TypeTemplates       Type = "templates"
	TypeWordlists       Type = "wordlists"
	TypeProfiles        Type = "profiles"
	TypeReportTemplates Type = "report-templates"
	TypePlaybooks       Type = "playbooks"
	TypePolicyPacks     Type = "policy-packs"
	TypeToolAdapters    Type = "tool-adapters"
	TypeSensors         Type = "sensors"
	TypeFeeds           Type = "feeds"
)

// Types lists every package type.
func Types() []Type {
	return []Type{TypeRules, TypeTemplates, TypeWordlists, TypeProfiles, TypeReportTemplates,
		TypePlaybooks, TypePolicyPacks, TypeToolAdapters, TypeSensors, TypeFeeds}
}

// IsPack reports whether packages of t are delivered as content packs.
func (t Type) IsPack() bool {
	return t == TypeRules || t == TypeTemplates || t == TypeWordlists
}

// IsExecutable reports whether packages of t are programs that run in the
// customer's network.
func (t Type) IsExecutable() bool { return t == TypeToolAdapters || t == TypeSensors }

// Artifact media types.
const (
	MediaGzip        = "application/gzip"
	MediaTar         = "application/x-tar"
	MediaPack        = "application/vnd.openctem.content-pack.v1.tar"
	MediaOCIIndex    = "application/vnd.oci.image.index.v1+json"
	MediaOCIManifest = "application/vnd.oci.image.manifest.v1+json"
	MediaFeedKeySet  = "application/vnd.openctem.feed-keyset+json"
)

// IsOCI reports whether m names an image held in a registry.
func IsOCI(m string) bool { return m == MediaOCIIndex || m == MediaOCIManifest }

// mediaByType lists the artifact media types each package type accepts.
var mediaByType = map[Type][]string{
	TypeRules:           {MediaGzip, MediaTar, MediaPack},
	TypeTemplates:       {MediaGzip, MediaTar, MediaPack},
	TypeWordlists:       {MediaGzip, MediaTar, MediaPack},
	TypeProfiles:        {MediaGzip, MediaTar},
	TypeReportTemplates: {MediaGzip, MediaTar},
	TypePlaybooks:       {MediaGzip, MediaTar},
	TypePolicyPacks:     {MediaGzip, MediaTar},
	TypeToolAdapters:    {MediaOCIIndex, MediaOCIManifest},
	TypeSensors:         {MediaOCIIndex, MediaOCIManifest},
	TypeFeeds:           {MediaFeedKeySet},
}

// reservedNamespaces are first-party only.
var reservedNamespaces = map[string]bool{
	"openctem": true, "openctemio": true, "official": true, "catalog": true, "platform": true, "system": true,
}

// IsReservedNamespace reports whether ns is reserved for first-party
// packages.
func IsReservedNamespace(ns string) bool { return reservedNamespaces[ns] }

// Artifact is what the package delivers, addressed by digest.
type Artifact struct {
	MediaType string `json:"media_type" yaml:"media_type"`
	Digest    string `json:"digest" yaml:"digest"`
	Size      int64  `json:"size" yaml:"size"`
	Ref       string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

// Compatibility holds the version ranges a package needs.
type Compatibility struct {
	Platform string `json:"platform" yaml:"platform"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
}

// Permissions is what the package declares it does. It is shown at install
// and enforced at run time; it never grants anything by itself.
type Permissions struct {
	Tier          string   `json:"tier" yaml:"tier"`
	SideEffects   string   `json:"side_effects" yaml:"side_effects"`
	Network       string   `json:"network" yaml:"network"`
	DeclaredHosts []string `json:"declared_hosts,omitempty" yaml:"declared_hosts,omitempty"`
	Credentials   []string `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	DataScopes    []string `json:"data_scopes,omitempty" yaml:"data_scopes,omitempty"`
}

// License is the package's license and what it allows.
type License struct {
	SPDX           string `json:"spdx" yaml:"spdx"`
	ServiceUse     bool   `json:"service_use" yaml:"service_use"`
	Redistribution bool   `json:"redistribution" yaml:"redistribution"`
}

// Dependency names another package and a version range.
type Dependency struct {
	ID      string `json:"id" yaml:"id"`
	Version string `json:"version" yaml:"version"`
}

// Provenance says where and how the artifact was built.
type Provenance struct {
	SourceRepository string `json:"source_repository,omitempty" yaml:"source_repository,omitempty"`
	SourceRevision   string `json:"source_revision,omitempty" yaml:"source_revision,omitempty"`
	BuildIdentity    string `json:"build_identity,omitempty" yaml:"build_identity,omitempty"`
	BuildIssuer      string `json:"build_issuer,omitempty" yaml:"build_issuer,omitempty"`
}

// Manifest is package.yaml.
type Manifest struct {
	APIVersion      string        `json:"apiVersion" yaml:"apiVersion"`
	ID              string        `json:"id" yaml:"id"`
	Version         string        `json:"version" yaml:"version"`
	Type            Type          `json:"type" yaml:"type"`
	Title           string        `json:"title" yaml:"title"`
	Summary         string        `json:"summary,omitempty" yaml:"summary,omitempty"`
	ContentKind     string        `json:"content_kind,omitempty" yaml:"content_kind,omitempty"`
	Artifact        Artifact      `json:"artifact" yaml:"artifact"`
	Compatibility   Compatibility `json:"compatibility" yaml:"compatibility"`
	Permissions     Permissions   `json:"permissions" yaml:"permissions"`
	License         License       `json:"license" yaml:"license"`
	Dependencies    []Dependency  `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Provenance      Provenance    `json:"provenance,omitzero" yaml:"provenance,omitempty"`
	SecurityContact string        `json:"security_contact,omitempty" yaml:"security_contact,omitempty"`
}

// Namespace is the part of the id before the slash.
func (m *Manifest) Namespace() string { ns, _, _ := strings.Cut(m.ID, "/"); return ns }

// Name is the part of the id after the slash.
func (m *Manifest) Name() string { _, n, _ := strings.Cut(m.ID, "/"); return n }

// ErrInvalid wraps every manifest validation error.
var ErrInvalid = errors.New("invalid package manifest")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Digest is "sha256:" + the hex SHA-256 of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func compiledSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
		if err != nil {
			schemaErr = err
			return
		}
		c := jsonschema.NewCompiler()
		const id = "https://openctem.io/schemas/package/v1.json"
		if err := c.AddResource(id, doc); err != nil {
			schemaErr = err
			return
		}
		schema, schemaErr = c.Compile(id)
	})
	return schema, schemaErr
}

// ParseManifest decodes package.yaml (YAML or JSON), checks it against the
// JSON schema, decodes it strictly and validates the rules the schema
// cannot express. raw is the exact bytes the manifest digest covers.
func ParseManifest(raw []byte) (*Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return nil, invalid("package.yaml is empty or over %d bytes", MaxManifestBytes)
	}
	doc, err := yamlToJSON(raw)
	if err != nil {
		return nil, invalid("package.yaml: %v", err)
	}
	s, err := compiledSchema()
	if err != nil {
		return nil, fmt.Errorf("package schema: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return nil, invalid("package.yaml: %v", err)
	}
	if err := s.Validate(inst); err != nil {
		return nil, invalid("%s", schemaMessage(err))
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, invalid("package.yaml: %v", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// schemaMessage keeps the first, most specific schema error short.
func schemaMessage(err error) string {
	var ve *jsonschema.ValidationError
	if errors.As(err, &ve) {
		for len(ve.Causes) > 0 {
			ve = ve.Causes[0]
		}
		loc := "/" + strings.Join(ve.InstanceLocation, "/")
		msg := ve.Error()
		if i := strings.LastIndex(msg, ": "); i >= 0 {
			msg = msg[i+2:]
		}
		return loc + ": " + msg
	}
	return err.Error()
}

// yamlToJSON converts one YAML document to JSON. Anchors, aliases, tags
// other than the core ones, and non-string keys are refused: a manifest is
// plain data.
func yamlToJSON(raw []byte) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("exactly one YAML document is allowed")
	}
	v, err := nodeValue(&root, 0)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

const maxYAMLDepth = 8

func nodeValue(n *yaml.Node, depth int) (any, error) {
	if depth > maxYAMLDepth {
		return nil, errors.New("nested too deeply")
	}
	if n.Anchor != "" {
		return nil, errors.New("anchors are not allowed")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, errors.New("empty document")
		}
		return nodeValue(n.Content[0], depth)
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return nil, errors.New("keys must be strings")
			}
			if _, dup := out[k.Value]; dup {
				return nil, fmt.Errorf("duplicate key %q", k.Value)
			}
			v, err := nodeValue(n.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := nodeValue(c, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		var v any
		switch n.Tag {
		case "!!str", "!!bool", "!!int", "!!null":
		default:
			return nil, fmt.Errorf("value %q: type %s is not allowed", clip(n.Value), n.Tag)
		}
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, errors.New("aliases are not allowed")
	}
}

func clip(s string) string {
	if len(s) > 32 {
		return s[:32] + "…"
	}
	return s
}

// Validate checks the rules the JSON schema cannot express. ParseManifest
// calls it; a manifest built in code (first-party generators, tests) calls
// it directly.
func (m *Manifest) Validate() error {
	if m.APIVersion != APIVersion {
		return invalid("apiVersion must be %s", APIVersion)
	}
	if !idPattern.MatchString(m.ID) {
		return invalid("id must be <namespace>/<name>")
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return invalid("version: %v", err)
	}
	media, ok := mediaByType[m.Type]
	if !ok {
		return invalid("unknown type %q", m.Type)
	}
	if err := checkText("title", m.Title, 80, false); err != nil {
		return err
	}
	if strings.TrimSpace(m.Title) == "" {
		return invalid("title is required")
	}
	if err := checkText("summary", m.Summary, 500, true); err != nil {
		return err
	}
	if err := m.validateArtifact(media); err != nil {
		return err
	}
	if err := m.validateCompatibility(); err != nil {
		return err
	}
	if err := m.validatePermissions(); err != nil {
		return err
	}
	if strings.TrimSpace(m.License.SPDX) == "" {
		return invalid("license.spdx is required")
	}
	if err := m.validateDependencies(); err != nil {
		return err
	}
	if NeedsPublisherIdentity(m.Type) &&
		(m.Provenance.BuildIdentity == "" || m.Provenance.BuildIssuer == "") {
		return invalid("provenance.build_identity and provenance.build_issuer are required for %s packages", m.Type)
	}
	return nil
}

func (m *Manifest) validateArtifact(media []string) error {
	a := m.Artifact
	allowed := false
	for _, x := range media {
		allowed = allowed || x == a.MediaType
	}
	if !allowed {
		return invalid("artifact.media_type %q is not allowed for %s packages", a.MediaType, m.Type)
	}
	if !digestPattern.MatchString(a.Digest) {
		return invalid("artifact.digest must be sha256:<64 hex>")
	}
	if a.Size < 1 || a.Size > MaxArtifactBytes {
		return invalid("artifact.size must be 1 to %d", MaxArtifactBytes)
	}
	if (a.Ref != "") != IsOCI(a.MediaType) {
		return invalid("artifact.ref is required for OCI artifacts and forbidden otherwise")
	}
	if m.Type.IsPack() {
		if err := contentpack.ValidateKind(m.ContentKind); err != nil {
			return invalid("content_kind: %v", err)
		}
	} else if m.ContentKind != "" {
		return invalid("content_kind is only for rules, templates and wordlists")
	}
	return nil
}

func (m *Manifest) validateCompatibility() error {
	if _, err := ParseRange(m.Compatibility.Platform); err != nil {
		return invalid("compatibility.platform: %v", err)
	}
	if m.Compatibility.Protocol != "" {
		if !m.Type.IsExecutable() {
			return invalid("compatibility.protocol is only for sensors and tool-adapters")
		}
		if _, err := ParseRange(m.Compatibility.Protocol); err != nil {
			return invalid("compatibility.protocol: %v", err)
		}
	}
	return nil
}

func (m *Manifest) validatePermissions() error {
	p := m.Permissions
	switch contentpack.Tier(p.Tier) {
	case contentpack.TierT0, contentpack.TierT1, contentpack.TierT2:
	default:
		return invalid("permissions.tier must be T0, T1 or T2")
	}
	if p.SideEffects == "destructive" && p.Tier != string(contentpack.TierT2) {
		return invalid("permissions.side_effects destructive requires tier T2")
	}
	if (p.Network == "declared-hosts") != (len(p.DeclaredHosts) > 0) {
		return invalid("permissions.declared_hosts is required with network declared-hosts and forbidden otherwise")
	}
	return nil
}

func (m *Manifest) validateDependencies() error {
	seen := map[string]bool{}
	for _, d := range m.Dependencies {
		if !idPattern.MatchString(d.ID) || d.ID == m.ID {
			return invalid("dependency %q", d.ID)
		}
		if seen[d.ID] {
			return invalid("dependency %q is listed twice", d.ID)
		}
		seen[d.ID] = true
		if _, err := ParseRange(d.Version); err != nil {
			return invalid("dependency %s: %v", d.ID, err)
		}
	}
	if len(m.Dependencies) > 0 && m.Type.IsExecutable() {
		return invalid("%s packages cannot have dependencies", m.Type)
	}
	return nil
}

// NeedsPublisherIdentity reports whether a package's artifact carries a
// keyless publisher signature that must be bound to a build identity: every
// file artifact, and OCI images (whose signature is checked against the
// identity where the image is pulled). Feed packages are signed by the
// feed's own root.
func NeedsPublisherIdentity(t Type) bool { return t != TypeFeeds }

func checkText(field, s string, maxRunes int, multiline bool) error {
	n := 0
	for _, r := range s {
		n++
		if r == unicode.ReplacementChar || (unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t'))) ||
			unicode.Is(unicode.Bidi_Control, r) {
			return invalid("%s has a control character", field)
		}
	}
	if n > maxRunes {
		return invalid("%s is over %d characters", field, maxRunes)
	}
	return nil
}
