### Security: AI triage masks hosts, addresses and e-mail addresses before the provider sees them

- The AI triage prompt now uses the organization's AI masking policy (Settings > AI > Data masking), like an AI agent's run: host names, IP addresses, e-mail addresses, URL ids and parameters, and the organization's and asset's names become placeholders; secrets always do. The code snippet is masked with every class.
- The model's answer is turned back into real values before it is stored, so the triage result shows real hosts and addresses. A placeholder the request never issued makes the result need review.
- The placeholder map lives in memory for one request only; it is never stored, logged or sent. If the policy cannot be read, nothing is sent and the job retries.
