package unit

// Security Fixes Test Index
//
// The security fix tests are placed in the packages where the functions under
// test are defined, so that unexported functions can be tested directly.
//
// Test locations:
//
//   SSRF (ValidateWebhookURL):
//     api/pkg/validator/security_test.go
//
//   X-Forwarded Header (isValidHostHeader):
//     api/internal/infra/http/handler/security_test.go
//
//   ExtraArgs Validation (validateExtraArgs):
//     agent/internal/executor/security_test.go
//
//   OAuth Redirect (isRedirectAllowed):
//     api/internal/infra/http/handler/oauth_security_test.go
//
// Run all security tests:
//   go test ./pkg/validator/ -run TestValidateWebhookURL -v
//   go test ./internal/infra/http/handler/ -run "TestIsValidHostHeader|TestOAuthRedirect" -v
//   cd ../agent && go test ./internal/executor/ -run TestValidateExtraArgs -v
