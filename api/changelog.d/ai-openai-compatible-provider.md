### Added: AI triage works with any OpenAI-compatible model server

- A new `openai_compatible` provider speaks the OpenAI chat-completions API at a base URL and model you set, so Azure OpenAI, vLLM, Ollama, LM Studio, LiteLLM, OpenRouter and cloud gateways work without a separate adapter. The API key is optional for it.
- Console, System > AI provider: choose the provider, base URL and model; a toggle "allow private addresses" lets a self-hosted server sit on a private network (RFC1918 and ULA ranges, plain http), and a model allow-list limits the platform model. The toggle is part of the existing super-admin, fresh-step-up, critical-audit change and is recorded in the audit row.
- Security: every provider call uses the SSRF-safe client (resolve once, dial the vetted address, no redirects). Loopback, link-local and cloud-metadata addresses, carrier-grade NAT and `localhost` are refused even with the toggle. An organization's own base URL is always public-only (https).

### Removed: the `azure_openai` provider and the `agent` AI mode

- Neither was ever usable (Azure returned "not yet implemented", the agent mode had no runtime). Use `openai_compatible` with the Azure OpenAI v1 endpoint instead.
