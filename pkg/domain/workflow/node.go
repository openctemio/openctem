package workflow

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// NodeType represents the type of workflow node.
type NodeType string

const (
	NodeTypeTrigger      NodeType = "trigger"
	NodeTypeCondition    NodeType = "condition"
	NodeTypeAction       NodeType = "action"
	NodeTypeNotification NodeType = "notification"
)

// IsValid checks if the node type is valid.
func (t NodeType) IsValid() bool {
	switch t {
	case NodeTypeTrigger, NodeTypeCondition, NodeTypeAction, NodeTypeNotification:
		return true
	}
	return false
}

// UIPosition represents the visual position in the workflow builder.
type UIPosition struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Node represents a node in a workflow graph.
type Node struct {
	ID         shared.ID
	WorkflowID shared.ID

	// Node definition
	NodeKey     string
	NodeType    NodeType
	Name        string
	Description string

	// Visual workflow builder
	UIPosition UIPosition

	// Configuration (depends on node type)
	Config NodeConfig

	// Timestamps
	CreatedAt time.Time
}

// NodeConfig contains the configuration for a workflow node.
// Different node types use different fields.
type NodeConfig struct {
	// Trigger config
	TriggerType   TriggerType    `json:"trigger_type,omitempty"`
	TriggerConfig map[string]any `json:"trigger_config,omitempty"`

	// Condition config
	ConditionExpr string `json:"condition_expr,omitempty"`

	// Action config
	ActionType   ActionType     `json:"action_type,omitempty"`
	ActionConfig map[string]any `json:"action_config,omitempty"`

	// Notification config
	NotificationType   NotificationType `json:"notification_type,omitempty"`
	NotificationConfig map[string]any   `json:"notification_config,omitempty"`
}

// TriggerType represents the type of trigger.
type TriggerType string

const (
	TriggerTypeManual          TriggerType = "manual"
	TriggerTypeSchedule        TriggerType = "schedule"
	TriggerTypeFindingCreated  TriggerType = "finding_created"
	TriggerTypeFindingUpdated  TriggerType = "finding_updated"
	TriggerTypeFindingAge      TriggerType = "finding_age"
	TriggerTypeAssetDiscovered TriggerType = "asset_discovered"
	TriggerTypeScanCompleted   TriggerType = "scan_completed"
	TriggerTypeWebhook         TriggerType = "webhook"
	// AI Triage triggers
	TriggerTypeAITriageCompleted TriggerType = "ai_triage_completed"
	TriggerTypeAITriageFailed    TriggerType = "ai_triage_failed"
)

// IsValid checks if the trigger type is valid.
func (t TriggerType) IsValid() bool {
	switch t {
	case TriggerTypeManual, TriggerTypeSchedule, TriggerTypeFindingCreated,
		TriggerTypeFindingUpdated, TriggerTypeFindingAge, TriggerTypeAssetDiscovered,
		TriggerTypeScanCompleted, TriggerTypeWebhook,
		TriggerTypeAITriageCompleted, TriggerTypeAITriageFailed:
		return true
	}
	return false
}

// ActionType represents the type of action.
type ActionType string

const (
	ActionTypeAssignUser      ActionType = "assign_user"
	ActionTypeAssignTeam      ActionType = "assign_team"
	ActionTypeUpdatePriority  ActionType = "update_priority"
	ActionTypeUpdateStatus    ActionType = "update_status"
	ActionTypeAddTags         ActionType = "add_tags"
	ActionTypeRemoveTags      ActionType = "remove_tags"
	ActionTypeCreateTicket    ActionType = "create_ticket"
	ActionTypeUpdateTicket    ActionType = "update_ticket"
	ActionTypeTriggerPipeline ActionType = "trigger_pipeline"
	ActionTypeTriggerScan     ActionType = "trigger_scan"
	ActionTypeHTTPRequest     ActionType = "http_request"
	ActionTypeRunScript       ActionType = "run_script"
	// AI Triage action
	ActionTypeTriggerAITriage ActionType = "trigger_ai_triage"
)

// IsValid checks if the action type is valid.
func (t ActionType) IsValid() bool {
	switch t {
	case ActionTypeAssignUser, ActionTypeAssignTeam, ActionTypeUpdatePriority,
		ActionTypeUpdateStatus, ActionTypeAddTags, ActionTypeRemoveTags,
		ActionTypeCreateTicket, ActionTypeUpdateTicket, ActionTypeTriggerPipeline,
		ActionTypeTriggerScan, ActionTypeHTTPRequest, ActionTypeRunScript,
		ActionTypeTriggerAITriage:
		return true
	}
	return false
}

// NotificationType represents the type of notification.
type NotificationType string

const (
	NotificationTypeSlack     NotificationType = "slack"
	NotificationTypeEmail     NotificationType = "email"
	NotificationTypeTeams     NotificationType = "teams"
	NotificationTypeWebhook   NotificationType = "webhook"
	NotificationTypePagerDuty NotificationType = "pagerduty"
)

// IsValid checks if the notification type is valid.
func (t NotificationType) IsValid() bool {
	switch t {
	case NotificationTypeSlack, NotificationTypeEmail, NotificationTypeTeams,
		NotificationTypeWebhook, NotificationTypePagerDuty:
		return true
	}
	return false
}

// NewNode creates a new workflow node.
func NewNode(
	workflowID shared.ID,
	nodeKey string,
	nodeType NodeType,
	name string,
) (*Node, error) {
	if nodeKey == "" {
		return nil, shared.NewDomainError("VALIDATION", "node_key is required", shared.ErrValidation)
	}
	if !nodeType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid node_type", shared.ErrValidation)
	}
	if name == "" {
		name = nodeKey
	}

	return &Node{
		ID:         shared.NewID(),
		WorkflowID: workflowID,
		NodeKey:    nodeKey,
		NodeType:   nodeType,
		Name:       name,
		UIPosition: UIPosition{X: 0, Y: 0},
		Config:     NodeConfig{},
		CreatedAt:  time.Now(),
	}, nil
}

// SetDescription sets the node description.
func (n *Node) SetDescription(desc string) {
	n.Description = desc
}

// SetUIPosition sets the visual position for the workflow builder.
func (n *Node) SetUIPosition(x, y float64) {
	n.UIPosition = UIPosition{X: x, Y: y}
}

// SetTriggerConfig sets the trigger configuration.
func (n *Node) SetTriggerConfig(triggerType TriggerType, config map[string]any) error {
	if n.NodeType != NodeTypeTrigger {
		return shared.NewDomainError("VALIDATION", "can only set trigger config on trigger nodes", shared.ErrValidation)
	}
	if !triggerType.IsValid() {
		return shared.NewDomainError("VALIDATION", "invalid trigger_type", shared.ErrValidation)
	}
	n.Config.TriggerType = triggerType
	n.Config.TriggerConfig = config
	return nil
}

// SetConditionConfig sets the condition configuration.
func (n *Node) SetConditionConfig(expr string) error {
	if n.NodeType != NodeTypeCondition {
		return shared.NewDomainError("VALIDATION", "can only set condition config on condition nodes", shared.ErrValidation)
	}
	n.Config.ConditionExpr = expr
	return nil
}

// SetActionConfig sets the action configuration.
func (n *Node) SetActionConfig(actionType ActionType, config map[string]any) error {
	if n.NodeType != NodeTypeAction {
		return shared.NewDomainError("VALIDATION", "can only set action config on action nodes", shared.ErrValidation)
	}
	if !actionType.IsValid() {
		return shared.NewDomainError("VALIDATION", "invalid action_type", shared.ErrValidation)
	}
	n.Config.ActionType = actionType
	n.Config.ActionConfig = config
	return nil
}

// SetNotificationConfig sets the notification configuration.
func (n *Node) SetNotificationConfig(notifType NotificationType, config map[string]any) error {
	if n.NodeType != NodeTypeNotification {
		return shared.NewDomainError("VALIDATION", "can only set notification config on notification nodes", shared.ErrValidation)
	}
	if !notifType.IsValid() {
		return shared.NewDomainError("VALIDATION", "invalid notification_type", shared.ErrValidation)
	}
	n.Config.NotificationType = notifType
	n.Config.NotificationConfig = config
	return nil
}

// Clone creates a copy of the node with a new ID.
func (n *Node) Clone() *Node {
	clone := &Node{
		ID:          shared.NewID(),
		WorkflowID:  n.WorkflowID,
		NodeKey:     n.NodeKey,
		NodeType:    n.NodeType,
		Name:        n.Name,
		Description: n.Description,
		UIPosition:  n.UIPosition,
		Config:      n.Config,
		CreatedAt:   time.Now(),
	}

	// Deep copy config maps
	if n.Config.TriggerConfig != nil {
		clone.Config.TriggerConfig = make(map[string]any)
		for k, v := range n.Config.TriggerConfig {
			clone.Config.TriggerConfig[k] = v
		}
	}
	if n.Config.ActionConfig != nil {
		clone.Config.ActionConfig = make(map[string]any)
		for k, v := range n.Config.ActionConfig {
			clone.Config.ActionConfig[k] = v
		}
	}
	if n.Config.NotificationConfig != nil {
		clone.Config.NotificationConfig = make(map[string]any)
		for k, v := range n.Config.NotificationConfig {
			clone.Config.NotificationConfig[k] = v
		}
	}

	return clone
}
