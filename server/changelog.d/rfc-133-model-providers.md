### Changed: RFC-133 designs the model provider layer of the AI worker

- New section 6a: the adapter families (OpenAI Chat Completions and Responses with Azure OpenAI and every OpenAI-compatible or local server, Anthropic Messages, Gemini and Vertex AI, Bedrock Converse, Cohere), the capability matrix, degradation rules, credential sources (platform-managed, worker-held, platform-provided; keyless cloud identities preferred) and authentication per family, the hardened HTTP client, retries and rate limits, tokens and the price table as data, region and retention, the settings schema the console stores, policy-safe fallback chains with circuit breakers, and the conformance kit.
- The threat model, decisions and plan, and the harness architecture note, are updated to match.
