package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
	"github.com/google/uuid"
)

// ActionHandler defines the interface for workflow action handlers.
type ActionHandler interface {
	// Execute executes the action and returns the output.
	Execute(ctx context.Context, input *ActionInput) (map[string]any, error)
}

// ActionInput contains the input for an action execution.
type ActionInput struct {
	TenantID     shared.ID
	WorkflowID   shared.ID
	RunID        shared.ID
	NodeKey      string
	ActionType   workflow.ActionType
	ActionConfig map[string]any
	TriggerData  map[string]any
	Context      map[string]any
}

// NotificationHandler defines the interface for notification handlers.
type NotificationHandler interface {
	// Send sends a notification and returns the result.
	Send(ctx context.Context, input *NotificationInput) (map[string]any, error)
}

// NotificationInput contains the input for a notification.
type NotificationInput struct {
	TenantID           shared.ID
	WorkflowID         shared.ID
	RunID              shared.ID
	NodeKey            string
	NotificationType   workflow.NotificationType
	NotificationConfig map[string]any
	TriggerData        map[string]any
	Context            map[string]any
}

// ConditionEvaluator defines the interface for condition evaluation.
type ConditionEvaluator interface {
	// Evaluate evaluates a condition expression against the given data.
	Evaluate(ctx context.Context, expression string, data map[string]any) (bool, error)
}

// ----------------------------------------------------------------------------
// Default Condition Evaluator
// ----------------------------------------------------------------------------

// DefaultConditionEvaluator provides a simple condition evaluator.
// It supports basic expressions like:
//   - "trigger.severity == 'critical'"
//   - "trigger.asset_type in ['server', 'database']"
//   - "upstream.check_status.output.is_valid == true"
//
// SEC-WF11: Includes expression length/complexity limits to prevent ReDoS.
type DefaultConditionEvaluator struct{}

// SEC-WF11: Expression limits
const (
	maxExpressionLength = 500 // Max characters in expression
	maxPathDepth        = 10  // Max depth of path resolution (e.g., a.b.c.d)
)

// Evaluate evaluates a condition expression.
func (e *DefaultConditionEvaluator) Evaluate(ctx context.Context, expression string, data map[string]any) (bool, error) {
	if expression == "" {
		return true, nil
	}

	// SEC-WF11: Check expression length
	if len(expression) > maxExpressionLength {
		return false, fmt.Errorf("expression too long: %d chars (max %d)", len(expression), maxExpressionLength)
	}

	// Simple expression evaluation
	// Format: "path.to.value OPERATOR value"
	// Operators: ==, !=, >, <, >=, <=, in, contains

	expr := strings.TrimSpace(expression)

	// Handle boolean literals
	if expr == "true" {
		return true, nil
	}
	if expr == "false" {
		return false, nil
	}

	// Try to parse comparison expressions
	operators := []string{"==", "!=", ">=", "<=", ">", "<", " in ", " contains "}
	for _, op := range operators {
		parts := strings.SplitN(expr, op, 2)
		if len(parts) == 2 {
			leftPath := strings.TrimSpace(parts[0])
			rightValue := strings.TrimSpace(parts[1])

			leftValue := e.resolvePath(leftPath, data)
			return e.compare(leftValue, strings.TrimSpace(op), rightValue)
		}
	}

	// Try to evaluate as a boolean path
	value := e.resolvePath(expr, data)
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		return v != "", nil
	case int, int64, float64:
		return v != 0, nil
	case nil:
		return false, nil
	default:
		return true, nil
	}
}

// resolvePath resolves a dot-separated path in the data map.
// SEC-WF11: Limited to maxPathDepth to prevent abuse.
func (e *DefaultConditionEvaluator) resolvePath(path string, data map[string]any) any {
	parts := strings.Split(path, ".")

	// SEC-WF11: Limit path depth
	if len(parts) > maxPathDepth {
		return nil
	}

	var current any = data

	for _, part := range parts {
		// SEC-WF11: Skip empty parts (e.g., from ".." in path)
		if part == "" {
			continue
		}
		switch c := current.(type) {
		case map[string]any:
			current = c[part]
		default:
			return nil
		}
	}

	return current
}

// compare compares two values with the given operator.
func (e *DefaultConditionEvaluator) compare(left any, op string, rightStr string) (bool, error) {
	op = strings.TrimSpace(op)

	// Parse the right value
	rightStr = strings.Trim(rightStr, "'\"")

	switch op {
	case "==":
		return fmt.Sprintf("%v", left) == rightStr, nil
	case "!=":
		return fmt.Sprintf("%v", left) != rightStr, nil
	case ">", "<", ">=", "<=":
		// Numeric comparison
		leftNum, rightNum, err := e.parseNumbers(left, rightStr)
		if err != nil {
			return false, err
		}
		switch op {
		case ">":
			return leftNum > rightNum, nil
		case "<":
			return leftNum < rightNum, nil
		case ">=":
			return leftNum >= rightNum, nil
		case "<=":
			return leftNum <= rightNum, nil
		}
	case "in":
		// Check if left is in right (array)
		rightStr = strings.Trim(rightStr, "[]")
		items := strings.Split(rightStr, ",")
		leftStr := fmt.Sprintf("%v", left)
		for _, item := range items {
			if strings.TrimSpace(strings.Trim(item, "'\"")) == leftStr {
				return true, nil
			}
		}
		return false, nil
	case "contains":
		// Check if left string contains right
		return strings.Contains(fmt.Sprintf("%v", left), rightStr), nil
	}

	return false, fmt.Errorf("unknown operator: %s", op)
}

// parseNumbers parses two values as numbers.
func (e *DefaultConditionEvaluator) parseNumbers(left any, right string) (float64, float64, error) {
	var leftNum float64
	switch v := left.(type) {
	case int:
		leftNum = float64(v)
	case int64:
		leftNum = float64(v)
	case float64:
		leftNum = v
	case string:
		if _, err := fmt.Sscanf(v, "%f", &leftNum); err != nil {
			return 0, 0, fmt.Errorf("cannot parse left value as number: %v", left)
		}
	default:
		return 0, 0, fmt.Errorf("cannot parse left value as number: %v", left)
	}

	var rightNum float64
	if _, err := fmt.Sscanf(right, "%f", &rightNum); err != nil {
		return 0, 0, fmt.Errorf("cannot parse right value as number: %s", right)
	}

	return leftNum, rightNum, nil
}

// ----------------------------------------------------------------------------
// HTTP Request Handler
// ----------------------------------------------------------------------------

// HTTPRequestHandler handles HTTP request actions.
// SECURITY: Includes SSRF protection via URL allowlist/denylist.
type HTTPRequestHandler struct {
	client       *http.Client
	logger       *logger.Logger
	blockedCIDRs []string      // Internal/private ranges to block
	maxTimeout   time.Duration // Maximum timeout allowed
	maxBodySize  int64         // Maximum response body size
}

// NewHTTPRequestHandler creates a new secure HTTPRequestHandler.
func NewHTTPRequestHandler(log *logger.Logger) *HTTPRequestHandler {
	return &HTTPRequestHandler{
		logger:      log,
		maxTimeout:  30 * time.Second,
		maxBodySize: 1024 * 1024, // 1MB
		// Block internal/private ranges by default (SSRF protection)
		blockedCIDRs: []string{
			"127.0.0.0/8",    // Loopback
			"10.0.0.0/8",     // Private
			"172.16.0.0/12",  // Private
			"192.168.0.0/16", // Private
			"169.254.0.0/16", // Link-local / Cloud metadata
			"::1/128",        // IPv6 loopback
			"fc00::/7",       // IPv6 private
			"fe80::/10",      // IPv6 link-local
		},
	}
}

// Execute executes an HTTP request action.
//
//nolint:cyclop,gocognit // HTTP request handler requires parsing many config options
func (h *HTTPRequestHandler) Execute(ctx context.Context, input *ActionInput) (map[string]any, error) {
	config := input.ActionConfig

	// Get URL (required)
	urlStr, ok := config["url"].(string)
	if !ok || urlStr == "" {
		return nil, fmt.Errorf("url is required for http_request action")
	}

	// SEC-WF01: Process URL with SAFE string interpolation (no template execution)
	urlStr = h.safeInterpolate(urlStr, input)

	// SEC-WF02: Validate URL for SSRF protection
	if err := h.validateURL(urlStr); err != nil {
		h.logger.Warn("HTTP request blocked by SSRF protection",
			"url", urlStr,
			"workflow_id", input.WorkflowID,
			"error", err,
		)
		return nil, fmt.Errorf("URL blocked by security policy: %w", err)
	}

	// Get method (default GET, only allow safe methods)
	method := "GET"
	if m, ok := config["method"].(string); ok {
		method = strings.ToUpper(m)
	}
	allowedMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	if !allowedMethods[method] {
		return nil, fmt.Errorf("HTTP method not allowed: %s", method)
	}

	// Get headers (filter sensitive headers)
	headers := make(map[string]string)
	if hdrs, ok := config["headers"].(map[string]any); ok {
		for k, v := range hdrs {
			headerKey := strings.ToLower(k)
			// Block headers that could be used for attacks
			if headerKey == "host" || headerKey == "x-forwarded-for" || headerKey == "x-real-ip" {
				continue
			}
			headers[k] = fmt.Sprintf("%v", v)
		}
	}

	// Get body with safe interpolation
	var body io.Reader
	if bodyData, ok := config["body"]; ok {
		switch b := bodyData.(type) {
		case string:
			processed := h.safeInterpolate(b, input)
			body = strings.NewReader(processed)
		case map[string]any:
			bodyJSON, err := json.Marshal(b)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal body: %w", err)
			}
			body = bytes.NewReader(bodyJSON)
			if _, ok := headers["Content-Type"]; !ok {
				headers["Content-Type"] = "application/json"
			}
		}
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Get timeout (capped at maxTimeout)
	timeout := 10 * time.Second // Default
	if t, ok := config["timeout"].(float64); ok {
		timeout = time.Duration(t) * time.Second
	}
	if timeout > h.maxTimeout {
		timeout = h.maxTimeout
	}

	// SEC-WF13: Create client with custom dialer for TOCTOU protection
	client := h.client
	if client == nil {
		// SEC-WF13: Custom dialer that validates IP at connection time
		// This prevents DNS rebinding TOCTOU attacks
		safeDialer := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}

		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Parse host:port
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address: %w", err)
				}

				// SEC-WF13: Resolve IP at connection time and validate
				ips, err := net.LookupIP(host)
				if err != nil {
					return nil, fmt.Errorf("DNS lookup failed: %w", err)
				}

				if len(ips) == 0 {
					return nil, fmt.Errorf("no IP addresses found for host")
				}

				// Check all resolved IPs
				var safeIP net.IP
				for _, ip := range ips {
					if !h.isBlockedIP(ip) {
						safeIP = ip
						break
					}
				}

				if safeIP == nil {
					return nil, fmt.Errorf("all resolved IPs are blocked")
				}

				// Connect directly to the validated IP
				return safeDialer.DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
			},
		}

		client = &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// Prevent redirect following to internal hosts
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("stopped after 3 redirects")
				}
				// Validate redirect URL (the dialer will also validate at connection time)
				if err := h.validateURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect blocked by security policy: %w", err)
				}
				return nil
			},
		}
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body with limit
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, h.maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response body as JSON if possible
	var respJSON any
	if err := json.Unmarshal(respBody, &respJSON); err != nil {
		respJSON = string(respBody)
	}

	output := map[string]any{
		"status_code": resp.StatusCode,
		"status":      resp.Status,
		"headers":     resp.Header,
		"body":        respJSON,
	}

	// Check for error status codes
	if resp.StatusCode >= 400 {
		return output, fmt.Errorf("HTTP request failed with status %d", resp.StatusCode)
	}

	return output, nil
}

// SEC-WF01: safeInterpolate performs simple variable substitution without template execution.
// This prevents SSTI attacks by not allowing arbitrary template functions.
// SEC-WF14: NodeKey is sanitized to prevent log injection.
func (h *HTTPRequestHandler) safeInterpolate(s string, input *ActionInput) string {
	// SEC-WF14: Sanitize NodeKey to prevent injection attacks
	safeNodeKey := sanitizeForLogging(input.NodeKey)

	// Only substitute known safe variables using simple string replacement
	replacements := map[string]string{
		"{{.tenant_id}}":   input.TenantID.String(),
		"{{.run_id}}":      input.RunID.String(),
		"{{.workflow_id}}": input.WorkflowID.String(),
		"{{.node_key}}":    safeNodeKey,
	}

	result := s
	for placeholder, value := range replacements {
		result = strings.ReplaceAll(result, placeholder, value)
	}

	// Also handle common patterns with spaces
	for placeholder, value := range replacements {
		spaced := strings.Replace(placeholder, "{{.", "{{ .", 1)
		spaced = strings.Replace(spaced, "}}", " }}", 1)
		result = strings.ReplaceAll(result, spaced, value)
	}

	return result
}

// SEC-WF02: validateURL validates a URL for SSRF protection.
// SEC-WF09: Fixed DNS rebinding by requiring successful resolution.
func (h *HTTPRequestHandler) validateURL(urlStr string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow http and https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("scheme not allowed: %s", parsedURL.Scheme)
	}

	// Get the hostname
	host := parsedURL.Hostname()
	if host == "" {
		return fmt.Errorf("empty hostname")
	}

	// Block localhost variants
	lowHost := strings.ToLower(host)
	if lowHost == "localhost" || lowHost == "127.0.0.1" || lowHost == "::1" {
		return fmt.Errorf("localhost not allowed")
	}

	// Check if it's a blocked hostname pattern
	blockedSuffixes := []string{".local", ".internal", ".localhost", ".lan", ".home", ".corp", ".intranet"}
	for _, suffix := range blockedSuffixes {
		if strings.HasSuffix(lowHost, suffix) {
			return fmt.Errorf("internal hostname pattern not allowed: %s", suffix)
		}
	}

	// SEC-WF09: If it's already an IP, validate directly
	if ip := net.ParseIP(host); ip != nil {
		if h.isBlockedIP(ip) {
			return fmt.Errorf("IP address %s is in blocked range", ip.String())
		}
		return nil
	}

	// SEC-WF09: Require successful DNS resolution (prevents DNS rebinding via unresolvable domains)
	ips, err := net.LookupIP(host)
	if err != nil {
		// SECURITY: Do NOT allow unresolvable domains - could be DNS rebinding setup
		return fmt.Errorf("cannot resolve hostname (DNS rebinding protection): %s", host)
	}

	if len(ips) == 0 {
		return fmt.Errorf("hostname resolved to no IP addresses: %s", host)
	}

	// Check if ALL resolved IPs are in blocked ranges (all must be safe)
	for _, ip := range ips {
		if h.isBlockedIP(ip) {
			return fmt.Errorf("IP address %s is in blocked range", ip.String())
		}
	}

	return nil
}

// isBlockedIP checks if an IP is in the blocked CIDR ranges.
func (h *HTTPRequestHandler) isBlockedIP(ip net.IP) bool {
	for _, cidr := range h.blockedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// Default Notification Handler
// ----------------------------------------------------------------------------

// DefaultNotificationHandler handles notification actions using the notification service.
type DefaultNotificationHandler struct {
	notificationService *NotificationService
	integrationService  *IntegrationService
	logger              *logger.Logger
}

// Send sends a notification.
func (h *DefaultNotificationHandler) Send(ctx context.Context, input *NotificationInput) (map[string]any, error) {
	config := input.NotificationConfig

	// Extract notification parameters
	title := h.resolveString(config, "title", input)
	body := h.resolveString(config, "body", input)
	severity := h.resolveString(config, "severity", input)
	url := h.resolveString(config, "url", input)

	if title == "" {
		title = "Workflow Notification"
	}
	if severity == "" {
		severity = "info"
	}

	// Handle different notification types
	switch input.NotificationType {
	case workflow.NotificationTypeSlack, workflow.NotificationTypeTeams, workflow.NotificationTypeWebhook:
		// Use integration service for direct channel notifications
		if h.integrationService != nil {
			integrationID, _ := config["integration_id"].(string)
			if integrationID != "" {
				// SEC-WF08: TenantID is always passed to ensure integration belongs to tenant
				// The integration service MUST verify ownership before sending
				result, err := h.integrationService.SendNotification(ctx, SendNotificationInput{
					IntegrationID: integrationID,
					TenantID:      input.TenantID.String(), // Always use the workflow's tenant
					Title:         title,
					Body:          body,
					Severity:      severity,
					URL:           url,
				})
				if err != nil {
					return nil, fmt.Errorf("failed to send notification: %w", err)
				}
				return map[string]any{
					"sent":           result.Success,
					"channel":        string(input.NotificationType),
					"integration_id": integrationID,
				}, nil
			}
		}

		// Fall through to notification service if no specific integration

	case workflow.NotificationTypeEmail:
		// Email notifications go through notification service
		if h.notificationService != nil {
			err := h.notificationService.EnqueueNotification(ctx, EnqueueNotificationParams{
				TenantID:      input.TenantID,
				EventType:     "workflow_notification",
				AggregateType: "workflow",
				AggregateID:   uuidPtrFromID(input.RunID),
				Title:         title,
				Body:          body,
				Severity:      severity,
				URL:           url,
				Metadata: map[string]any{
					"workflow_id": input.WorkflowID.String(),
					"run_id":      input.RunID.String(),
					"node_key":    input.NodeKey,
				},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to enqueue notification: %w", err)
			}
			return map[string]any{
				"enqueued": true,
				"channel":  "email",
			}, nil
		}

	case workflow.NotificationTypePagerDuty:
		// PagerDuty specific handling
		if h.integrationService != nil {
			integrationID, _ := config["integration_id"].(string)
			if integrationID != "" {
				// PagerDuty requires specific fields
				fields := map[string]string{
					"workflow_id": input.WorkflowID.String(),
					"run_id":      input.RunID.String(),
				}
				if extra, ok := config["fields"].(map[string]any); ok {
					for k, v := range extra {
						fields[k] = fmt.Sprintf("%v", v)
					}
				}

				// SEC-WF08: TenantID is always passed to ensure integration belongs to tenant
				result, err := h.integrationService.SendNotification(ctx, SendNotificationInput{
					IntegrationID: integrationID,
					TenantID:      input.TenantID.String(), // Always use the workflow's tenant
					Title:         title,
					Body:          body,
					Severity:      severity,
					URL:           url,
					Fields:        fields,
				})
				if err != nil {
					return nil, fmt.Errorf("failed to send PagerDuty notification: %w", err)
				}
				return map[string]any{
					"sent":           result.Success,
					"channel":        "pagerduty",
					"integration_id": integrationID,
				}, nil
			}
		}
	}

	// Default: use notification service outbox
	if h.notificationService != nil {
		err := h.notificationService.EnqueueNotification(ctx, EnqueueNotificationParams{
			TenantID:      input.TenantID,
			EventType:     "workflow_notification",
			AggregateType: "workflow",
			AggregateID:   uuidPtrFromID(input.RunID),
			Title:         title,
			Body:          body,
			Severity:      severity,
			URL:           url,
			Metadata: map[string]any{
				"workflow_id":       input.WorkflowID.String(),
				"run_id":            input.RunID.String(),
				"node_key":          input.NodeKey,
				"notification_type": string(input.NotificationType),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to enqueue notification: %w", err)
		}
		return map[string]any{
			"enqueued": true,
			"channel":  string(input.NotificationType),
		}, nil
	}

	return nil, fmt.Errorf("no notification service configured")
}

// resolveString resolves a string value from config using SAFE interpolation.
// SEC-WF03: Uses safeInterpolateNotification to prevent SSTI attacks.
func (h *DefaultNotificationHandler) resolveString(config map[string]any, key string, input *NotificationInput) string {
	value, ok := config[key].(string)
	if !ok {
		return ""
	}

	// Use safe interpolation instead of template execution
	return h.safeInterpolateNotification(value, input)
}

// SEC-WF03: safeInterpolateNotification performs simple variable substitution.
// This prevents SSTI attacks by not allowing arbitrary template functions.
// SEC-WF14: NodeKey is sanitized to prevent log injection.
func (h *DefaultNotificationHandler) safeInterpolateNotification(s string, input *NotificationInput) string {
	// SEC-WF14: Sanitize NodeKey to prevent injection attacks
	safeNodeKey := sanitizeForLogging(input.NodeKey)

	// Only substitute known safe variables using simple string replacement
	replacements := map[string]string{
		"{{.tenant_id}}":   input.TenantID.String(),
		"{{.run_id}}":      input.RunID.String(),
		"{{.workflow_id}}": input.WorkflowID.String(),
		"{{.node_key}}":    safeNodeKey,
	}

	result := s
	for placeholder, value := range replacements {
		result = strings.ReplaceAll(result, placeholder, value)
	}

	// Also handle common patterns with spaces
	for placeholder, value := range replacements {
		spaced := strings.Replace(placeholder, "{{.", "{{ .", 1)
		spaced = strings.Replace(spaced, "}}", " }}", 1)
		result = strings.ReplaceAll(result, spaced, value)
	}

	// Handle nested trigger data access (limited depth)
	// e.g., {{.trigger.severity}} -> actual value
	if input.TriggerData != nil {
		for k, v := range input.TriggerData {
			strVal := fmt.Sprintf("%v", v)
			result = strings.ReplaceAll(result, fmt.Sprintf("{{.trigger.%s}}", k), strVal)
			result = strings.ReplaceAll(result, fmt.Sprintf("{{ .trigger.%s }}", k), strVal)
		}
	}

	return result
}

// uuidPtrFromID converts a shared.ID to a *uuid.UUID pointer.
func uuidPtrFromID(id shared.ID) *uuid.UUID {
	parsed, err := uuid.Parse(id.String())
	if err != nil {
		return nil
	}
	return &parsed
}

// SEC-WF14: sanitizeForLogging removes potentially dangerous characters from strings
// used in logs or interpolation to prevent log injection and other attacks.
func sanitizeForLogging(s string) string {
	// Limit length
	const maxLen = 100
	if len(s) > maxLen {
		s = s[:maxLen]
	}

	// Remove/replace dangerous characters
	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			result.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			result.WriteRune(r)
		case r >= '0' && r <= '9':
			result.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			result.WriteRune(r)
		default:
			// Replace other characters with underscore
			result.WriteRune('_')
		}
	}

	return result.String()
}
