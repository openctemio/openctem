package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// ProviderOpenAICompatible is the provider kind for any server that speaks
// the OpenAI chat-completions API: Azure OpenAI's v1 endpoint, vLLM, Ollama,
// LiteLLM, OpenRouter, LM Studio and cloud gateways. The caller sets the
// base URL and the model.
const ProviderOpenAICompatible = "openai_compatible"

// OpenAICompatibleConfig configures an OpenAI-compatible provider.
type OpenAICompatibleConfig struct {
	// BaseURL is the API root, for example https://llm.example.com/v1. The
	// chat-completions path is appended.
	BaseURL string
	// APIKey is optional: a server inside the network may not need one.
	APIKey string
	Model  string // required
	// AllowPrivate lets the base URL be on a private network (RFC1918 / ULA)
	// and use plain http. Only a platform administrator may set it; an
	// organization's URL is always public-only (https).
	AllowPrivate bool
	Timeout      time.Duration
	MaxRetries   int
}

// ValidateBaseURL checks an OpenAI-compatible base URL and returns it
// normalized (no trailing slash). It rejects a missing or non-http(s) scheme,
// plain http unless allowPrivate, credentials, query or fragment in the URL,
// "localhost" and cloud-metadata names, and a host that resolves to a blocked
// address: loopback, link-local and cloud metadata always, RFC1918 / ULA
// unless allowPrivate. The dialer repeats the address check at connect time
// (resolve once, dial the vetted IP), which defeats DNS rebinding.
func ValidateBaseURL(ctx context.Context, raw string, allowPrivate bool) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: base URL is not a valid URL", ErrInvalidProvider)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowPrivate:
	default:
		return "", fmt.Errorf("%w: base URL must use https", ErrInvalidProvider)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: base URL must not contain credentials, a query or a fragment", ErrInvalidProvider)
	}
	check := httpsec.ValidateHost
	if allowPrivate {
		check = httpsec.ValidateHostAllowPrivate
	}
	if err := check(ctx, u.Host); err != nil {
		return "", fmt.Errorf("%w: base URL host is not allowed: %v", ErrInvalidProvider, err)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// NewOpenAICompatibleProvider creates a provider for an OpenAI-compatible
// server. Every call goes through an SSRF-guarded client; the base URL is
// not resolved here.
func NewOpenAICompatibleProvider(cfg OpenAICompatibleConfig) (*OpenAIProvider, error) {
	if cfg.Model == "" {
		return nil, fmt.Errorf("%w: model is required", ErrProviderNotConfigured)
	}
	u, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && cfg.AllowPrivate)) || u.User != nil {
		return nil, fmt.Errorf("%w: base URL is required (https)", ErrProviderNotConfigured)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}
	var client *http.Client
	if cfg.AllowPrivate {
		client = httpsec.PrivateAllowedHTTPClient(timeout)
	} else {
		client = httpsec.SafeHTTPClient(timeout)
	}
	// A redirect could move the request (and the key) to another host.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &OpenAIProvider{
		name:       ProviderOpenAICompatible,
		endpoint:   strings.TrimRight(u.String(), "/") + "/chat/completions",
		apiKey:     cfg.APIKey,
		model:      cfg.Model,
		httpClient: client,
		maxRetries: maxRetries,
	}, nil
}
