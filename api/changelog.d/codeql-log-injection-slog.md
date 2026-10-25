### Changed: CodeQL log-injection no longer flags escaped slog attributes

- Go code scanning replaces `go/log-injection` with `openctem/go/log-injection` (`.github/codeql/go-queries`): the same sources, sinks and sanitizers, minus the key-value attributes of `log/slog` calls, which slog's text and JSON handlers escape. The standard query flagged those even next to a CR/LF strip; 1,082 such alerts had been dismissed by hand. A slog message argument and every other logger are still checked. `pkg/logger/forging_test.go` pins that an attribute value with CR/LF stays on one line in both formats.
- `.github/codeql/**` is a security-sensitive path.
- Two remaining flows are sanitised: the e-mail sender's failure log (its logger is an interface) and the refused trust names printed by `ci-trust-scope-plan`.
