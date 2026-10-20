package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// The request is the chat-completions shape at <base>/chat/completions, with
// the bearer key and the configured model; the key is optional.
func TestOpenAICompatible_RequestShape(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"model":"llama3","choices":[{"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`)
	}))
	defer srv.Close()

	for _, key := range []string{"sk-fake-0123456789", ""} {
		p, err := NewOpenAICompatibleProvider(OpenAICompatibleConfig{BaseURL: "https://llm.example.com/v1/", APIKey: key, Model: "llama3"})
		require.NoError(t, err)
		// The endpoint is the public hostname; point the transport at the test
		// server (loopback is rightly refused by the guard).
		assert.Equal(t, "https://llm.example.com/v1/chat/completions", p.endpoint)
		p.endpoint = srv.URL + "/v1/chat/completions"
		p.httpClient = srv.Client()

		resp, err := p.Complete(context.Background(), CompletionRequest{SystemPrompt: "sys", UserPrompt: "hi", JSONMode: true, MaxTokens: 5})
		require.NoError(t, err)
		assert.Equal(t, "OK", resp.Content)
		assert.Equal(t, 4, resp.TotalTokens)
		assert.Equal(t, "/v1/chat/completions", gotPath)
		assert.Equal(t, "llama3", gotBody["model"])
		assert.Equal(t, "json_object", gotBody["response_format"].(map[string]any)["type"])
		msgs := gotBody["messages"].([]any)
		assert.Len(t, msgs, 2)
		if key == "" {
			assert.Empty(t, gotAuth, "no key: no Authorization header")
		} else {
			assert.Equal(t, "Bearer "+key, gotAuth)
		}
		assert.Equal(t, ProviderOpenAICompatible, p.Name())
		assert.NoError(t, p.Validate())
	}
}

// A remote error body is not relayed (it is the server's text, not ours).
func TestOpenAICompatible_ErrorBodyNotRelayed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"internal host db-7 refused","type":"x"}}`)
	}))
	defer srv.Close()
	p, err := NewOpenAICompatibleProvider(OpenAICompatibleConfig{BaseURL: "https://llm.example.com/v1", Model: "m"})
	require.NoError(t, err)
	p.endpoint, p.httpClient = srv.URL, srv.Client()
	_, err = p.Complete(context.Background(), CompletionRequest{UserPrompt: "hi"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "db-7")
	assert.Contains(t, err.Error(), "400")
}

func TestOpenAICompatible_NoRedirectFollowed(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	p, err := NewOpenAICompatibleProvider(OpenAICompatibleConfig{BaseURL: "https://llm.example.com/v1", APIKey: "sk-fake-0123456789", Model: "m", MaxRetries: 1})
	require.NoError(t, err)
	p.endpoint = srv.URL
	c := srv.Client()
	c.CheckRedirect = p.httpClient.CheckRedirect
	p.httpClient = c
	_, err = p.Complete(context.Background(), CompletionRequest{UserPrompt: "hi"})
	require.Error(t, err)
	assert.Zero(t, hits, "the key must not follow a redirect to another host")
}

// SECURITY: an organization's endpoint is public-only. Each of these is
// refused when the provider is built and again at dial time.
func TestOrgBaseURL_PrivateLoopbackMetadataRefused(t *testing.T) {
	ctx := context.Background()
	refused := []string{
		"https://127.0.0.1/v1",
		"https://localhost/v1",
		"https://[::1]/v1",
		"https://169.254.169.254/latest",
		"https://metadata.google.internal/v1",
		"https://10.0.0.5/v1",
		"https://192.168.1.10/v1",
		"https://172.16.0.9/v1",
		"https://[fd12:3456::1]/v1",
		"https://100.64.0.1/v1",
		"https://[64:ff9b::a9fe:a9fe]/v1",
		"http://llm.example.com/v1", // plain http for an org
		"ftp://llm.example.com/v1",
		"https://user:pass@llm.example.com/v1",
		"https://llm.example.com/v1?key=1",
		"",
		"not a url",
	}
	for _, u := range refused {
		_, err := ValidateBaseURL(ctx, u, false)
		assert.Error(t, err, "must refuse %q", u)
	}
	got, err := ValidateBaseURL(ctx, " https://93.184.216.34/v1/ ", false)
	require.NoError(t, err)
	assert.Equal(t, "https://93.184.216.34/v1", got)
}

// The platform toggle opens RFC1918 and http, never loopback or metadata.
func TestPlatformBaseURL_PrivateOnlyWithToggle(t *testing.T) {
	ctx := context.Background()
	_, err := ValidateBaseURL(ctx, "http://10.0.0.5:11434/v1", false)
	assert.Error(t, err)
	got, err := ValidateBaseURL(ctx, "http://10.0.0.5:11434/v1", true)
	require.NoError(t, err)
	assert.Equal(t, "http://10.0.0.5:11434/v1", got)
	for _, u := range []string{"http://127.0.0.1:11434/v1", "http://localhost:11434/v1", "http://169.254.169.254/v1", "http://100.64.0.1/v1"} {
		_, err := ValidateBaseURL(ctx, u, true)
		assert.Error(t, err, "must refuse %q even with the toggle", u)
	}
}

// The dial is guarded too: a provider pointed at the loopback test server
// never connects, with or without the platform toggle.
func TestOpenAICompatible_DialRefusesLoopback(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	for _, allow := range []bool{false, true} {
		p, err := NewOpenAICompatibleProvider(OpenAICompatibleConfig{BaseURL: srv.URL, Model: "m", AllowPrivate: allow, MaxRetries: 1, Timeout: 2 * time.Second})
		if err != nil { // https required without the toggle
			require.False(t, allow)
			continue
		}
		_, err = p.Complete(context.Background(), CompletionRequest{UserPrompt: "hi"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ssrf guard")
	}
	assert.Zero(t, hits)
}

func TestNewOpenAICompatibleProvider_Requires(t *testing.T) {
	_, err := NewOpenAICompatibleProvider(OpenAICompatibleConfig{BaseURL: "https://x.example.com", Model: ""})
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
	_, err = NewOpenAICompatibleProvider(OpenAICompatibleConfig{BaseURL: "", Model: "m"})
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
	_, err = NewOpenAICompatibleProvider(OpenAICompatibleConfig{BaseURL: "http://x.example.com", Model: "m"})
	assert.ErrorIs(t, err, ErrProviderNotConfigured, "plain http needs the platform toggle")
}

// Factory: the organization's BYOK openai_compatible path refuses a private URL.
func TestFactory_BYOKOpenAICompatible(t *testing.T) {
	f := NewFactory(config.AITriageConfig{TimeoutSeconds: 5})
	_, err := f.CreateProviderForTenant("t1", tenant.AISettings{Mode: tenant.AIModeBYOK, Provider: tenant.LLMProviderOpenAICompatible,
		APIKey: "sk-fake-0123456789", BaseURL: "https://10.0.0.5/v1", ModelOverride: "m"})
	assert.ErrorIs(t, err, ErrInvalidProvider)
	p, err := f.CreateProviderForTenant("t1", tenant.AISettings{Mode: tenant.AIModeBYOK, Provider: tenant.LLMProviderOpenAICompatible,
		APIKey: "sk-fake-0123456789", BaseURL: "https://93.184.216.34/v1", ModelOverride: "m"})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(p.Name(), ProviderOpenAICompatible))
}

// A removed mode fails closed: it never falls back to the platform key.
func TestFactory_RemovedModeFailsClosed(t *testing.T) {
	f := NewFactory(config.AITriageConfig{AnthropicAPIKey: "sk-ant-fake-0123456789"})
	_, err := f.CreateProviderForTenant("t1", tenant.AISettings{Mode: tenant.AIMode("removed")})
	assert.ErrorIs(t, err, ErrInvalidProvider)
}
