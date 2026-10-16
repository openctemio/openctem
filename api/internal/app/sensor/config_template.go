package sensor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorConfigTemplateService renders the snippets that install and configure
// a sensor (docker run, Compose, Kubernetes, Helm, yaml, env, cli) from
// filesystem-loaded templates.
//
// Templates live in <templates_dir>/<set>/<format>.tmpl, one directory per
// install snippet set (a product's versions.yaml install key), and use Go
// text/template syntax. They are product data, not platform code: a new
// sensor product adds a directory (and a catalog entry) and needs no API
// change. Operators can edit the .tmpl files in place, or add a set,
// without rebuilding the API or frontend; changes are picked up on restart,
// or live if Reload() is called. A missing shipped file falls back to the
// built-in template of the same name (identical to the shipped file; a test
// keeps them in step).
//
// Every snippet must work as pasted, for the release the image tag pins (the
// product's latest release in versions.yaml): tests run `bash -n` on the
// shell snippets and parse the YAML ones.
type SensorConfigTemplateService struct {
	templatesDir string
	logger       *logger.Logger

	mu        sync.RWMutex
	templates map[string]*template.Template // key: templateKey(set, format)
}

// templateFormats is every format, in response order.
var templateFormats = []string{"yaml", "env", "docker", "cli", "compose", "kubernetes", "helm", "policy"}

// installCollector is the snippet set of a collector sensor: it runs the
// inventory collector, with its own image and settings, not the scanner.
const installCollector = "collector"

// InstallSensor is the snippet set of the scanning sensor. Every set is the
// directory <set>/ of <format>.tmpl files; a product's set (versions.yaml
// install) may cover only some formats, but always docker.
const InstallSensor = "sensor"

// installSetRE is a snippet set name (a directory of the templates dir).
var installSetRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// templateNames is every template loaded: the shipped ones (each format of
// the scanning sensor, the collector's and each product set's files).
func templateNames() []string {
	out := make([]string, 0, len(builtinTemplates))
	for name := range builtinTemplates {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// HasInstallSet reports whether the snippet set has at least its docker
// template, the one every set must offer.
func (s *SensorConfigTemplateService) HasInstallSet(set string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.templates[templateKey(set, "docker")]
	return ok
}

func templateKey(set, format string) string {
	if set == "" {
		set = InstallSensor
	}
	return set + "/" + format
}

// SensorTemplateData is the data passed to every sensor config template.
type SensorTemplateData struct {
	Sensor *sensordom.Sensor
	// APIKey is the sensor's key, available only right after it was created
	// or rotated; empty renders a reference to $OPENCTEM_API_KEY instead.
	APIKey string
	// BaseURL is the public URL sensors connect to (SENSOR_PUBLIC_API_URL,
	// else APP_URL).
	BaseURL string
	// Image is the sensor image with its pinned tag, e.g.
	// ghcr.io/openctemio/sensor:v0.4.2. Never "latest".
	Image string
	// ImageTag is Image's tag (the product release it pins).
	ImageTag string
	// Install is the product's snippet set (InstallSensor when empty); a
	// collector sensor always uses the collector's set.
	Install string
	// ReleaseIdentity is the workflow that signs the product's image
	// (versions.yaml release_identity); the snippets that check the
	// signature use it + "@refs/tags/" + ImageTag. Empty: no check shown.
	ReleaseIdentity string
	// CACert is the PEM of the platform's certificate authority when it uses
	// a private one (SENSOR_CA_CERT_FILE); empty for a publicly trusted
	// certificate. The snippets install it and point SSL_CERT_DIR at it.
	CACert      string
	GeneratedAt string // RFC3339 timestamp

	// SeccompURL is where the install commands download the sensor's
	// seccomp profile (BaseURL + SeccompProfilePath) and SeccompSHA256 the
	// digest they check; Render fills both.
	SeccompURL    string
	SeccompSHA256 string

	// Policy is what the sensor-local policy template (RFC-040 §5.7,
	// policy.tmpl) is prefilled with; PolicyFromZones builds it.
	Policy PolicyTemplateData
}

// PolicyTemplateData prefills the sensor-local policy the install dialog
// offers the network owner: the ranges of the sensor's scan zones.
type PolicyTemplateData struct {
	// Ranges are the CIDRs of the sensor's zones (targets.allow). Empty with
	// Open false: the sensor has no zone yet and the owner lists them.
	Ranges []string
	// Open: one of the sensor's zones is the default zone, which receives
	// public targets no range covers, so the policy sets no allow list.
	Open bool
	// AllowPrivate: a range is private (RFC 1918, ULA); the policy allows
	// private targets and the snippets set SENSOR_ALLOW_PRIVATE_TARGETS=1.
	AllowPrivate bool
}

// PolicyFromZones builds the policy prefill from the tenant's zones: the
// ranges of the zones sensorID is assigned to.
func PolicyFromZones(zones []*scanzone.Zone, sensorID shared.ID) PolicyTemplateData {
	var out PolicyTemplateData
	for _, z := range zones {
		if z == nil || !slices.Contains(z.SensorIDs, sensorID) {
			continue
		}
		if z.IsDefault {
			out.Open = true
		}
		for _, r := range z.Ranges {
			s := r.Masked().String()
			if !slices.Contains(out.Ranges, s) {
				out.Ranges = append(out.Ranges, s)
			}
			if r.Addr().IsPrivate() {
				out.AllowPrivate = true
			}
		}
	}
	slices.Sort(out.Ranges)
	return out
}

// NewSensorConfigTemplateService loads templates from the given directory.
// If the directory doesn't exist or any template fails to parse, the
// service falls back to built-in defaults so the API never fails to start.
func NewSensorConfigTemplateService(templatesDir string, log *logger.Logger) *SensorConfigTemplateService {
	s := &SensorConfigTemplateService{
		templatesDir: templatesDir,
		logger:       log.With("service", "sensor_config_template"),
		templates:    make(map[string]*template.Template),
	}
	if err := s.Reload(); err != nil {
		s.logger.Warn("failed to load sensor config templates, using built-in defaults",
			"templates_dir", templatesDir,
			"error", err)
		s.loadBuiltins()
	}
	return s
}

// loadBuiltins installs the built-in templates (they always parse; a test
// renders them).
func (s *SensorConfigTemplateService) loadBuiltins() {
	loaded := make(map[string]*template.Template, 2*len(templateFormats))
	for _, format := range templateNames() {
		loaded[format] = template.Must(template.New(format).Funcs(templateFuncs()).Parse(builtinTemplates[format]))
	}
	s.mu.Lock()
	s.templates = loaded
	s.mu.Unlock()
}

// Reload re-reads all template files from disk: every shipped template
// (falling back to its built-in copy when the file is missing) and every
// other <set>/<format>.tmpl in the directory, so a product's snippet set
// added on disk is served without an API change. Safe to call at runtime.
func (s *SensorConfigTemplateService) Reload() error {
	names := templateNames()
	if files, err := filepath.Glob(filepath.Join(s.templatesDir, "*", "*.tmpl")); err == nil {
		for _, f := range files {
			set, format := filepath.Base(filepath.Dir(f)), strings.TrimSuffix(filepath.Base(f), ".tmpl")
			name := templateKey(set, format)
			if installSetRE.MatchString(set) && slices.Contains(templateFormats, format) && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	loaded := make(map[string]*template.Template, len(names))
	for _, format := range names {
		path := filepath.Join(s.templatesDir, filepath.FromSlash(format)+".tmpl")
		content, err := os.ReadFile(path)
		if err != nil {
			s.logger.Debug("template file missing, using the built-in one",
				"format", format, "path", path, "error", err)
			content = []byte(builtinTemplates[format])
		}

		tmpl, err := template.New(format).Funcs(templateFuncs()).Parse(string(content))
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", format, err)
		}
		loaded[format] = tmpl
	}

	s.mu.Lock()
	s.templates = loaded
	s.mu.Unlock()
	s.logger.Info("sensor config templates loaded", "count", len(loaded), "dir", s.templatesDir)
	return nil
}

// RenderedTemplates is the output of rendering all templates for one sensor.
type RenderedTemplates struct {
	YAML       string `json:"yaml"`
	Env        string `json:"env"`
	Docker     string `json:"docker"`
	CLI        string `json:"cli"`
	Compose    string `json:"compose"`
	Kubernetes string `json:"kubernetes"`
	Helm       string `json:"helm"`
	// Policy is the sensor-local policy template (sensor-policy.yaml).
	Policy string `json:"policy"`
}

// Render renders every template format with the given sensor data.
func (s *SensorConfigTemplateService) Render(data SensorTemplateData) (*RenderedTemplates, error) {
	s.mu.RLock()
	tmpls := s.templates
	s.mu.RUnlock()

	if data.GeneratedAt == "" {
		data.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if data.Sensor == nil {
		return nil, fmt.Errorf("render sensor templates: no sensor")
	}
	if data.SeccompURL == "" {
		data.SeccompURL = strings.TrimRight(data.BaseURL, "/") + SeccompProfilePath
	}
	if data.SeccompSHA256 == "" {
		data.SeccompSHA256 = SeccompProfileSHA256
	}
	if data.CACert != "" && !strings.HasSuffix(data.CACert, "\n") {
		data.CACert += "\n"
	}

	if data.ImageTag == "" {
		if i := strings.LastIndex(data.Image, ":"); i > strings.LastIndex(data.Image, "/") {
			data.ImageTag = data.Image[i+1:]
		}
	}
	set := data.Install
	if data.Sensor.Type.IsCollector() {
		set = installCollector
	}
	out := make(map[string]string, len(templateFormats))
	for _, format := range templateFormats {
		tmpl, ok := tmpls[templateKey(set, format)]
		if !ok {
			if set == "" || set == InstallSensor || format == "docker" {
				return nil, fmt.Errorf("template %q not loaded", templateKey(set, format))
			}
			// A product set covers only the formats it ships; the
			// others are left empty and the console hides them.
			continue
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("failed to render %s template: %w", format, err)
		}
		out[format] = buf.String()
	}
	return &RenderedTemplates{
		YAML: out["yaml"], Env: out["env"], Docker: out["docker"], CLI: out["cli"],
		Compose: out["compose"], Kubernetes: out["kubernetes"], Helm: out["helm"], Policy: out["policy"],
	}, nil
}

// =============================================================================
// Template Helper Functions
// =============================================================================

var slugRegexp = regexp.MustCompile(`[^a-z0-9-]+`)

// toolNameRegexp is a tool name that is safe to put in a shell snippet. Tool
// names are set by tenant admins; anything else is dropped from the snippets.
var toolNameRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)

// Tool-name normalization table — raw tool name → scanner name the
// sensor config template expects. Kept as one source of truth so both
// template helpers normalise consistently.
var toolToScannerName = map[string]string{
	"trivy": "trivy-fs",
}

// defaultToolName is the fallback used by firstTool when the template
// receives an empty tool list.
const defaultToolName = "semgrep"

// normalizeToolName applies toolToScannerName, returning the input
// unchanged when no mapping exists.
func normalizeToolName(tool string) string {
	if mapped, ok := toolToScannerName[tool]; ok {
		return mapped
	}
	return tool
}

// safeTools keeps the tool names that are safe in a snippet, lowercased.
func safeTools(tools []string) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		t = strings.ToLower(strings.TrimSpace(t))
		if toolNameRegexp.MatchString(t) {
			out = append(out, t)
		}
	}
	return out
}

// slugify converts a name to a docker/kubernetes-friendly name.
func slugify(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = slugRegexp.ReplaceAllString(s, "")
	s = strings.Trim(s, "-")
	if len(s) > 50 {
		s = strings.Trim(s[:50], "-")
	}
	if s == "" {
		return "openctem-sensor"
	}
	return s
}

// shellQuote quotes a value for a POSIX shell (single quotes).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// yamlQuote quotes a value as a YAML double-quoted scalar.
func yamlQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}

// indent prefixes every non-empty line of s with n spaces.
func indent(n int, s string) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = pad + l
		}
	}
	return strings.Join(lines, "\n")
}

// imageTag returns the tag of an image reference ("" without one).
func imageTag(image string) string {
	ref := image
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[i+1:]
	}
	return ""
}

// templateFuncs are the functions exposed to templates.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		// product and docs name the instance brand in comments
		// (docs/architecture/brand.md).
		"product": brand.Name,
		"docs":    func() string { return brand.Instance().Docs() },
		// toScannerName maps a tool name to its scanner name
		// (e.g., "trivy" -> "trivy-fs").
		"toScannerName": normalizeToolName,
		// firstTool returns the first safe tool in the list, or
		// defaultToolName if there is none.
		"firstTool": func(tools []string) string {
			if t := safeTools(tools); len(t) > 0 {
				return normalizeToolName(t[0])
			}
			return defaultToolName
		},
		// tools returns the safe tool names.
		"tools": safeTools,
		// toolList joins the safe tool names with commas ("" for none).
		"toolList": func(tools []string) string { return strings.Join(safeTools(tools), ",") },
		// slugify converts a name to a docker/kubernetes-friendly name.
		"slugify":    slugify,
		"shellQuote": shellQuote,
		"yamlQuote":  yamlQuote,
		"indent":     indent,
		"imageTag":   imageTag,
		// replaceComma escapes commas for a helm --set value.
		"replaceComma": func(s string) string { return strings.ReplaceAll(s, ",", `\,`) },
		// isDaemon reports whether the sensor runs continuously (as opposed
		// to a one-shot CI run).
		"isDaemon": func(s *sensordom.Sensor) bool { return s != nil && !s.IsOneShot() },
	}
}
