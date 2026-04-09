package app

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/logger"
)

// AgentConfigTemplateService renders agent configuration templates
// (yaml, env, docker, cli) from filesystem-loaded templates.
//
// Templates live in <templates_dir>/{yaml,env,docker,cli}.tmpl and use
// Go text/template syntax. Operators can edit the .tmpl files in place
// without rebuilding the API or frontend — changes are picked up on
// restart, or live if Reload() is called.
//
// The service caches parsed templates after first load. Call Reload() to
// pick up file changes without restart.
type AgentConfigTemplateService struct {
	templatesDir string
	logger       *logger.Logger

	mu        sync.RWMutex
	templates map[string]*template.Template // key: format name (yaml, env, docker, cli)
}

// AgentTemplateData is the data passed to every agent config template.
type AgentTemplateData struct {
	Agent       *agent.Agent
	APIKey      string // May be empty if not freshly created/regenerated
	BaseURL     string // Public API URL agents should connect to
	GeneratedAt string // RFC3339 timestamp
}

// NewAgentConfigTemplateService loads templates from the given directory.
// If the directory doesn't exist or any template fails to parse, the
// service falls back to built-in defaults so the API never fails to start.
func NewAgentConfigTemplateService(templatesDir string, log *logger.Logger) *AgentConfigTemplateService {
	s := &AgentConfigTemplateService{
		templatesDir: templatesDir,
		logger:       log.With("service", "agent_config_template"),
		templates:    make(map[string]*template.Template),
	}
	if err := s.Reload(); err != nil {
		s.logger.Warn("failed to load agent config templates, using built-in defaults",
			"templates_dir", templatesDir,
			"error", err)
	}
	return s
}

// Reload re-reads all template files from disk. Safe to call at runtime.
func (s *AgentConfigTemplateService) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	formats := []string{"yaml", "env", "docker", "cli"}
	loaded := make(map[string]*template.Template, len(formats))

	for _, format := range formats {
		path := filepath.Join(s.templatesDir, format+".tmpl")
		content, err := os.ReadFile(path)
		if err != nil {
			s.logger.Warn("template file missing, will use built-in default",
				"format", format,
				"path", path,
				"error", err)
			content = []byte(builtinTemplates[format])
		}

		tmpl, err := template.New(format).Funcs(templateFuncs()).Parse(string(content))
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", format, err)
		}
		loaded[format] = tmpl
	}

	s.templates = loaded
	s.logger.Info("agent config templates loaded", "count", len(loaded), "dir", s.templatesDir)
	return nil
}

// RenderedTemplates is the output of rendering all templates for one agent.
type RenderedTemplates struct {
	YAML   string `json:"yaml"`
	Env    string `json:"env"`
	Docker string `json:"docker"`
	CLI    string `json:"cli"`
}

// Render renders all four template formats with the given agent data.
// Returns user-friendly content (no internal errors leaked).
func (s *AgentConfigTemplateService) Render(data AgentTemplateData) (*RenderedTemplates, error) {
	s.mu.RLock()
	tmpls := s.templates
	s.mu.RUnlock()

	if data.GeneratedAt == "" {
		data.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}

	result := &RenderedTemplates{}
	for _, format := range []string{"yaml", "env", "docker", "cli"} {
		tmpl, ok := tmpls[format]
		if !ok {
			return nil, fmt.Errorf("template %q not loaded", format)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("failed to render %s template: %w", format, err)
		}
		switch format {
		case "yaml":
			result.YAML = buf.String()
		case "env":
			result.Env = buf.String()
		case "docker":
			result.Docker = buf.String()
		case "cli":
			result.CLI = buf.String()
		}
	}
	return result, nil
}

// =============================================================================
// Template Helper Functions
// =============================================================================

var slugRegexp = regexp.MustCompile(`[^a-z0-9-]+`)

// templateFuncs are the functions exposed to templates.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		// toScannerName maps a tool name to its scanner name (e.g., "trivy" -> "trivy-fs").
		"toScannerName": func(tool string) string {
			switch tool {
			case "trivy":
				return "trivy-fs"
			default:
				return tool
			}
		},
		// firstTool returns the first tool in the list, or "semgrep" if empty.
		"firstTool": func(tools []string) string {
			if len(tools) == 0 {
				return "semgrep"
			}
			tool := tools[0]
			if tool == "trivy" {
				return "trivy-fs"
			}
			return tool
		},
		// slugify converts a name to a docker-friendly slug.
		"slugify": func(name string) string {
			s := strings.ToLower(name)
			s = strings.ReplaceAll(s, " ", "-")
			s = slugRegexp.ReplaceAllString(s, "")
			if s == "" {
				return "agent"
			}
			return s
		},
	}
}

// =============================================================================
// Built-in Template Defaults
// =============================================================================
//
// These are used when the template files on disk are missing or unreadable.
// They are intentionally kept minimal — operators should override by editing
// configs/agent-templates/*.tmpl on disk.

var builtinTemplates = map[string]string{
	"yaml": `# Agent Configuration for {{.Agent.Name}}
# Generated by OpenCTEM at {{.GeneratedAt}}

agent:
  name: {{.Agent.Name}}
  region: "{{.Agent.Region}}"
  enable_commands: true
  command_poll_interval: 30s
  heartbeat_interval: 1m

server:
  base_url: {{.BaseURL}}
  api_key: {{.APIKey}}
  agent_id: {{.Agent.ID}}

scanners:
{{- if .Agent.Tools}}
{{- range .Agent.Tools}}
  - name: {{toScannerName .}}
    enabled: true
{{- end}}
{{- else}}
  - name: semgrep
    enabled: true
{{- end}}
`,
	"env": `# Environment Variables for {{.Agent.Name}}

export API_URL={{.BaseURL}}
export API_KEY={{.APIKey}}
export AGENT_ID={{.Agent.ID}}
{{- if .Agent.Region}}
export REGION={{.Agent.Region}}
{{- end}}
`,
	"docker": `# Docker run command for {{.Agent.Name}}

docker run -d \
  --name {{slugify .Agent.Name}} \
  -v /path/to/scan:/code:ro \
  -e API_URL={{.BaseURL}} \
  -e API_KEY={{.APIKey}} \
  -e AGENT_ID={{.Agent.ID}} \
{{- if .Agent.Region}}
  -e REGION={{.Agent.Region}} \
{{- end}}
  openctemio/agent:latest \
  -daemon -config /app/agent.yaml
`,
	"cli": `# CLI Commands for {{.Agent.Name}}

# One-shot scan
./agent -tool {{firstTool .Agent.Tools}} -target /path/to/project -push

# Daemon mode
./agent -daemon -config agent.yaml

# With env vars
export API_URL={{.BaseURL}}
export API_KEY={{.APIKey}}
./agent -tool {{firstTool .Agent.Tools}} -target . -push
`,
}
