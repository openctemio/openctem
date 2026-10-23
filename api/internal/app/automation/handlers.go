package automation

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/outbox"

	"github.com/google/uuid"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
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
	ActionType   automationdom.ActionType
	ActionConfig map[string]any
	TriggerData  map[string]any
	Context      map[string]any
	// Principal is the person the step runs as: the member who started a
	// manual run, otherwise the automation's owner (the person the step
	// authorization already checked). A step that starts other work (a scan)
	// starts it as this person, never as another account.
	Principal shared.ID
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
	NotificationType   automationdom.NotificationType
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

	// Handle boolean literals — use strconv so "TRUE"/"1"/"0" are also
	// accepted the same way humans write them in workflow configs.
	if b, berr := strconv.ParseBool(expr); berr == nil {
		return b, nil
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
// Default Notification Handler
// ----------------------------------------------------------------------------

// DefaultNotificationHandler handles notification actions using the notification service.
type DefaultNotificationHandler struct {
	notificationService *outbox.Service
	integrationService  *integration.IntegrationService
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
	case automationdom.NotificationTypeSlack, automationdom.NotificationTypeTeams, automationdom.NotificationTypeWebhook:
		// Use integration service for direct channel notifications
		if h.integrationService != nil {
			integrationID, _ := config["integration_id"].(string)
			if integrationID != "" {
				// SEC-WF08: TenantID is always passed to ensure integration belongs to tenant
				// The integration service MUST verify ownership before sending
				result, err := h.integrationService.SendNotification(ctx, integration.SendNotificationInput{
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

	case automationdom.NotificationTypeEmail:
		// Email notifications go through notification service
		if h.notificationService != nil {
			err := h.notificationService.Enqueue(ctx, outbox.EnqueueParams{
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

	}

	// Default: use notification service outbox
	if h.notificationService != nil {
		err := h.notificationService.Enqueue(ctx, outbox.EnqueueParams{
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
