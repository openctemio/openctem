package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// WorkflowHandler handles HTTP requests for workflows.
type WorkflowHandler struct {
	service   *app.WorkflowService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewWorkflowHandler creates a new WorkflowHandler.
func NewWorkflowHandler(service *app.WorkflowService, v *validator.Validator, log *logger.Logger) *WorkflowHandler {
	return &WorkflowHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "workflow"),
	}
}

// --- Workflow Request/Response Types ---

// CreateWorkflowRequest represents the request body for creating a workflow.
type CreateWorkflowRequest struct {
	Name        string              `json:"name" validate:"required,min=1,max=255"`
	Description string              `json:"description" validate:"max=1000"`
	Tags        []string            `json:"tags" validate:"max=10,dive,max=50"`
	Nodes       []NodeRequest       `json:"nodes" validate:"min=1,max=50,dive"`
	Edges       []CreateEdgeRequest `json:"edges" validate:"max=100,dive"`
}

// NodeRequest represents a node in the workflow request.
type NodeRequest struct {
	NodeKey     string                     `json:"node_key" validate:"required,min=1,max=100"`
	NodeType    string                     `json:"node_type" validate:"required,oneof=trigger condition action notification"`
	Name        string                     `json:"name" validate:"required,min=1,max=255"`
	Description string                     `json:"description" validate:"max=1000"`
	UIPosition  *WorkflowUIPositionRequest `json:"ui_position"`
	Config      *NodeConfigRequest         `json:"config"`
}

// WorkflowUIPositionRequest represents a visual position in the workflow builder.
type WorkflowUIPositionRequest struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// NodeConfigRequest represents node configuration.
type NodeConfigRequest struct {
	TriggerType        string         `json:"trigger_type,omitempty"`
	TriggerConfig      map[string]any `json:"trigger_config,omitempty"`
	ConditionExpr      string         `json:"condition_expr,omitempty"`
	ActionType         string         `json:"action_type,omitempty"`
	ActionConfig       map[string]any `json:"action_config,omitempty"`
	NotificationType   string         `json:"notification_type,omitempty"`
	NotificationConfig map[string]any `json:"notification_config,omitempty"`
}

// CreateEdgeRequest represents an edge in the workflow request.
type CreateEdgeRequest struct {
	SourceNodeKey string `json:"source_node_key" validate:"required,min=1,max=100"`
	TargetNodeKey string `json:"target_node_key" validate:"required,min=1,max=100"`
	SourceHandle  string `json:"source_handle" validate:"max=50"`
	Label         string `json:"label" validate:"max=100"`
}

// WorkflowResponse represents the response for a workflow.
type WorkflowResponse struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	Name           string         `json:"name"`
	Description    string         `json:"description,omitempty"`
	IsActive       bool           `json:"is_active"`
	Tags           []string       `json:"tags,omitempty"`
	Nodes          []NodeResponse `json:"nodes,omitempty"`
	Edges          []EdgeResponse `json:"edges,omitempty"`
	TotalRuns      int            `json:"total_runs"`
	SuccessfulRuns int            `json:"successful_runs"`
	FailedRuns     int            `json:"failed_runs"`
	LastRunID      *string        `json:"last_run_id,omitempty"`
	LastRunAt      *string        `json:"last_run_at,omitempty"`
	LastRunStatus  string         `json:"last_run_status,omitempty"`
	CreatedBy      *string        `json:"created_by,omitempty"`
	CreatedAt      string         `json:"created_at"`
	UpdatedAt      string         `json:"updated_at"`
}

// NodeResponse represents a node in the workflow response.
type NodeResponse struct {
	ID          string                     `json:"id"`
	WorkflowID  string                     `json:"workflow_id"`
	NodeKey     string                     `json:"node_key"`
	NodeType    string                     `json:"node_type"`
	Name        string                     `json:"name"`
	Description string                     `json:"description,omitempty"`
	UIPosition  WorkflowUIPositionResponse `json:"ui_position"`
	Config      NodeConfigResponse         `json:"config"`
	CreatedAt   string                     `json:"created_at"`
}

// WorkflowUIPositionResponse represents a visual position in the response.
type WorkflowUIPositionResponse struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// NodeConfigResponse represents node configuration in the response.
type NodeConfigResponse struct {
	TriggerType        string         `json:"trigger_type,omitempty"`
	TriggerConfig      map[string]any `json:"trigger_config,omitempty"`
	ConditionExpr      string         `json:"condition_expr,omitempty"`
	ActionType         string         `json:"action_type,omitempty"`
	ActionConfig       map[string]any `json:"action_config,omitempty"`
	NotificationType   string         `json:"notification_type,omitempty"`
	NotificationConfig map[string]any `json:"notification_config,omitempty"`
}

// EdgeResponse represents an edge in the workflow response.
type EdgeResponse struct {
	ID            string `json:"id"`
	WorkflowID    string `json:"workflow_id"`
	SourceNodeKey string `json:"source_node_key"`
	TargetNodeKey string `json:"target_node_key"`
	SourceHandle  string `json:"source_handle,omitempty"`
	Label         string `json:"label,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// --- Run Request/Response Types ---

// TriggerWorkflowRequest represents the request body for triggering a workflow run.
type TriggerWorkflowRequest struct {
	TriggerType string         `json:"trigger_type" validate:"omitempty,oneof=manual schedule finding_created finding_updated finding_age asset_discovered scan_completed webhook"`
	TriggerData map[string]any `json:"trigger_data"`
}

// WorkflowRunResponse represents the response for a workflow run.
type WorkflowRunResponse struct {
	ID             string            `json:"id"`
	WorkflowID     string            `json:"workflow_id"`
	TenantID       string            `json:"tenant_id"`
	TriggerType    string            `json:"trigger_type"`
	TriggerData    map[string]any    `json:"trigger_data,omitempty"`
	Status         string            `json:"status"`
	StartedAt      *string           `json:"started_at,omitempty"`
	CompletedAt    *string           `json:"completed_at,omitempty"`
	TotalNodes     int               `json:"total_nodes"`
	CompletedNodes int               `json:"completed_nodes"`
	FailedNodes    int               `json:"failed_nodes"`
	TriggeredBy    *string           `json:"triggered_by,omitempty"`
	ErrorMessage   string            `json:"error_message,omitempty"`
	NodeRuns       []NodeRunResponse `json:"node_runs,omitempty"`
	CreatedAt      string            `json:"created_at"`
}

// NodeRunResponse represents a node run in the response.
type NodeRunResponse struct {
	ID            string         `json:"id"`
	WorkflowRunID string         `json:"workflow_run_id"`
	NodeID        string         `json:"node_id"`
	NodeKey       string         `json:"node_key"`
	NodeType      string         `json:"node_type"`
	Status        string         `json:"status"`
	Input         map[string]any `json:"input,omitempty"`
	Output        map[string]any `json:"output,omitempty"`
	StartedAt     *string        `json:"started_at,omitempty"`
	CompletedAt   *string        `json:"completed_at,omitempty"`
	ErrorMessage  string         `json:"error_message,omitempty"`
	ErrorCode     string         `json:"error_code,omitempty"`
}

// --- Workflow Handlers ---

// CreateWorkflow handles POST /api/v1/workflows
func (h *WorkflowHandler) CreateWorkflow(w http.ResponseWriter, r *http.Request) {
	var req CreateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID) // May be empty for service accounts

	// Convert nodes
	nodes := make([]app.CreateNodeInput, len(req.Nodes))
	for i, n := range req.Nodes {
		nodes[i] = app.CreateNodeInput{
			NodeKey:     n.NodeKey,
			NodeType:    workflow.NodeType(n.NodeType),
			Name:        n.Name,
			Description: n.Description,
		}
		if n.UIPosition != nil {
			nodes[i].UIPositionX = n.UIPosition.X
			nodes[i].UIPositionY = n.UIPosition.Y
		}
		if n.Config != nil {
			nodes[i].Config = toNodeConfig(n.Config)
		}
	}

	// Convert edges
	edges := make([]app.CreateEdgeInput, len(req.Edges))
	for i, e := range req.Edges {
		edges[i] = app.CreateEdgeInput{
			SourceNodeKey: e.SourceNodeKey,
			TargetNodeKey: e.TargetNodeKey,
			SourceHandle:  e.SourceHandle,
			Label:         e.Label,
		}
	}

	input := app.CreateWorkflowInput{
		TenantID:    tenantUUID,
		UserID:      userUUID,
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		Nodes:       nodes,
		Edges:       edges,
	}

	wf, err := h.service.CreateWorkflow(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toWorkflowResponse(wf))
}

// GetWorkflow handles GET /api/v1/workflows/{id}
func (h *WorkflowHandler) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	wf, err := h.service.GetWorkflow(r.Context(), tenantUUID, workflowUUID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toWorkflowResponse(wf))
}

// ListWorkflows handles GET /api/v1/workflows
func (h *WorkflowHandler) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	var isActive *bool
	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		active := activeStr == queryParamTrue
		isActive = &active
	}

	input := app.ListWorkflowsInput{
		TenantID: tenantUUID,
		IsActive: isActive,
		Tags:     parseQueryArray(r.URL.Query().Get("tags")),
		Search:   r.URL.Query().Get("search"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	result, err := h.service.ListWorkflows(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*WorkflowResponse, len(result.Data))
	for i, wf := range result.Data {
		items[i] = toWorkflowResponse(wf)
	}

	resp := map[string]interface{}{
		"items":       items,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateWorkflowRequest represents the request body for updating a workflow.
type UpdateWorkflowRequest struct {
	Name        *string  `json:"name" validate:"omitempty,min=1,max=255"`
	Description *string  `json:"description" validate:"omitempty,max=1000"`
	Tags        []string `json:"tags" validate:"max=10,dive,max=50"`
	IsActive    *bool    `json:"is_active"`
}

// UpdateWorkflow handles PUT /api/v1/workflows/{id}
func (h *WorkflowHandler) UpdateWorkflow(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req UpdateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID)

	input := app.UpdateWorkflowInput{
		TenantID:    tenantUUID,
		UserID:      userUUID,
		WorkflowID:  workflowUUID,
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		IsActive:    req.IsActive,
	}

	wf, err := h.service.UpdateWorkflow(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toWorkflowResponse(wf))
}

// DeleteWorkflow handles DELETE /api/v1/workflows/{id}
func (h *WorkflowHandler) DeleteWorkflow(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID)

	if err := h.service.DeleteWorkflow(r.Context(), tenantUUID, userUUID, workflowUUID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateWorkflowGraphRequest represents the request body for updating a workflow's graph.
type UpdateWorkflowGraphRequest struct {
	Name        *string             `json:"name" validate:"omitempty,min=1,max=255"`
	Description *string             `json:"description" validate:"omitempty,max=1000"`
	Tags        []string            `json:"tags" validate:"max=10,dive,max=50"`
	Nodes       []NodeRequest       `json:"nodes" validate:"min=1,max=50,dive"`
	Edges       []CreateEdgeRequest `json:"edges" validate:"max=100,dive"`
}

// UpdateWorkflowGraph handles PUT /api/v1/workflows/{id}/graph
// This endpoint atomically replaces the entire workflow graph (nodes and edges).
func (h *WorkflowHandler) UpdateWorkflowGraph(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req UpdateWorkflowGraphRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID)

	// Convert nodes
	nodes := make([]app.CreateNodeInput, len(req.Nodes))
	for i, n := range req.Nodes {
		nodes[i] = app.CreateNodeInput{
			NodeKey:     n.NodeKey,
			NodeType:    workflow.NodeType(n.NodeType),
			Name:        n.Name,
			Description: n.Description,
		}
		if n.UIPosition != nil {
			nodes[i].UIPositionX = n.UIPosition.X
			nodes[i].UIPositionY = n.UIPosition.Y
		}
		if n.Config != nil {
			nodes[i].Config = toNodeConfig(n.Config)
		}
	}

	// Convert edges
	edges := make([]app.CreateEdgeInput, len(req.Edges))
	for i, e := range req.Edges {
		edges[i] = app.CreateEdgeInput{
			SourceNodeKey: e.SourceNodeKey,
			TargetNodeKey: e.TargetNodeKey,
			SourceHandle:  e.SourceHandle,
			Label:         e.Label,
		}
	}

	input := app.UpdateWorkflowGraphInput{
		TenantID:    tenantUUID,
		UserID:      userUUID,
		WorkflowID:  workflowUUID,
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		Nodes:       nodes,
		Edges:       edges,
	}

	wf, err := h.service.UpdateWorkflowGraph(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toWorkflowResponse(wf))
}

// --- Node Handlers ---

// AddNode handles POST /api/v1/workflows/{id}/nodes
func (h *WorkflowHandler) AddNode(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req NodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID)

	input := app.AddNodeInput{
		TenantID:    tenantUUID,
		UserID:      userUUID,
		WorkflowID:  workflowUUID,
		NodeKey:     req.NodeKey,
		NodeType:    workflow.NodeType(req.NodeType),
		Name:        req.Name,
		Description: req.Description,
	}
	if req.UIPosition != nil {
		input.UIPositionX = req.UIPosition.X
		input.UIPositionY = req.UIPosition.Y
	}
	if req.Config != nil {
		input.Config = toNodeConfig(req.Config)
	}

	node, err := h.service.AddNode(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toNodeResponse(node))
}

// UpdateNodeRequest represents the request body for updating a node.
type UpdateNodeRequest struct {
	Name        *string                    `json:"name" validate:"omitempty,min=1,max=255"`
	Description *string                    `json:"description" validate:"omitempty,max=1000"`
	UIPosition  *WorkflowUIPositionRequest `json:"ui_position"`
	Config      *NodeConfigRequest         `json:"config"`
}

// UpdateNode handles PUT /api/v1/workflows/{id}/nodes/{nodeId}
func (h *WorkflowHandler) UpdateNode(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	nodeID := chi.URLParam(r, "nodeId")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req UpdateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	nodeUUID, err := shared.IDFromString(nodeID)
	if err != nil {
		apierror.BadRequest("Invalid node ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID)

	input := app.UpdateNodeInput{
		TenantID:    tenantUUID,
		UserID:      userUUID,
		WorkflowID:  workflowUUID,
		NodeID:      nodeUUID,
		Name:        req.Name,
		Description: req.Description,
	}
	if req.UIPosition != nil {
		input.UIPositionX = &req.UIPosition.X
		input.UIPositionY = &req.UIPosition.Y
	}
	if req.Config != nil {
		cfg := toNodeConfig(req.Config)
		input.Config = &cfg
	}

	node, err := h.service.UpdateNode(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toNodeResponse(node))
}

// DeleteNode handles DELETE /api/v1/workflows/{id}/nodes/{nodeId}
func (h *WorkflowHandler) DeleteNode(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	nodeID := chi.URLParam(r, "nodeId")
	tenantID := middleware.GetTenantID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	nodeUUID, err := shared.IDFromString(nodeID)
	if err != nil {
		apierror.BadRequest("Invalid node ID").WriteJSON(w)
		return
	}

	if err := h.service.DeleteNode(r.Context(), tenantUUID, workflowUUID, nodeUUID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Edge Handlers ---

// AddEdge handles POST /api/v1/workflows/{id}/edges
func (h *WorkflowHandler) AddEdge(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateEdgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID)

	input := app.AddEdgeInput{
		TenantID:      tenantUUID,
		UserID:        userUUID,
		WorkflowID:    workflowUUID,
		SourceNodeKey: req.SourceNodeKey,
		TargetNodeKey: req.TargetNodeKey,
		SourceHandle:  req.SourceHandle,
		Label:         req.Label,
	}

	edge, err := h.service.AddEdge(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toEdgeResponse(edge))
}

// DeleteEdge handles DELETE /api/v1/workflows/{id}/edges/{edgeId}
func (h *WorkflowHandler) DeleteEdge(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	edgeID := chi.URLParam(r, "edgeId")
	tenantID := middleware.GetTenantID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	edgeUUID, err := shared.IDFromString(edgeID)
	if err != nil {
		apierror.BadRequest("Invalid edge ID").WriteJSON(w)
		return
	}

	if err := h.service.DeleteEdge(r.Context(), tenantUUID, workflowUUID, edgeUUID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Run Handlers ---

// TriggerWorkflow handles POST /api/v1/workflows/{id}/runs
func (h *WorkflowHandler) TriggerWorkflow(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req TriggerWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	workflowUUID, err := shared.IDFromString(workflowID)
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID)

	triggerType := workflow.TriggerTypeManual
	if req.TriggerType != "" {
		triggerType = workflow.TriggerType(req.TriggerType)
	}

	input := app.TriggerWorkflowInput{
		TenantID:    tenantUUID,
		UserID:      userUUID,
		WorkflowID:  workflowUUID,
		TriggerType: triggerType,
		TriggerData: req.TriggerData,
	}

	run, err := h.service.TriggerWorkflow(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toWorkflowRunResponse(run))
}

// GetRun handles GET /api/v1/workflow-runs/{id}
func (h *WorkflowHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	runUUID, err := shared.IDFromString(runID)
	if err != nil {
		apierror.BadRequest("Invalid run ID").WriteJSON(w)
		return
	}

	run, err := h.service.GetRun(r.Context(), tenantUUID, runUUID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toWorkflowRunResponse(run))
}

// ListRuns handles GET /api/v1/workflow-runs
func (h *WorkflowHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	input := app.ListWorkflowRunsInput{
		TenantID: tenantUUID,
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	if wfID := r.URL.Query().Get("workflow_id"); wfID != "" {
		wfUUID, err := shared.IDFromString(wfID)
		if err == nil {
			input.WorkflowID = &wfUUID
		}
	}

	if status := r.URL.Query().Get("status"); status != "" {
		s := workflow.RunStatus(status)
		input.Status = &s
	}

	result, err := h.service.ListRuns(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*WorkflowRunResponse, len(result.Data))
	for i, run := range result.Data {
		items[i] = toWorkflowRunResponse(run)
	}

	resp := map[string]interface{}{
		"items":       items,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CancelRun handles POST /api/v1/workflow-runs/{id}/cancel
func (h *WorkflowHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	runUUID, err := shared.IDFromString(runID)
	if err != nil {
		apierror.BadRequest("Invalid run ID").WriteJSON(w)
		return
	}

	userUUID, _ := shared.IDFromString(userID)

	if err := h.service.CancelRun(r.Context(), tenantUUID, userUUID, runUUID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Conversion Helpers ---

func toNodeConfig(req *NodeConfigRequest) workflow.NodeConfig {
	if req == nil {
		return workflow.NodeConfig{}
	}
	return workflow.NodeConfig{
		TriggerType:        workflow.TriggerType(req.TriggerType),
		TriggerConfig:      req.TriggerConfig,
		ConditionExpr:      req.ConditionExpr,
		ActionType:         workflow.ActionType(req.ActionType),
		ActionConfig:       req.ActionConfig,
		NotificationType:   workflow.NotificationType(req.NotificationType),
		NotificationConfig: req.NotificationConfig,
	}
}

func toWorkflowResponse(wf *workflow.Workflow) *WorkflowResponse {
	resp := &WorkflowResponse{
		ID:             wf.ID.String(),
		TenantID:       wf.TenantID.String(),
		Name:           wf.Name,
		Description:    wf.Description,
		IsActive:       wf.IsActive,
		Tags:           wf.Tags,
		TotalRuns:      wf.TotalRuns,
		SuccessfulRuns: wf.SuccessfulRuns,
		FailedRuns:     wf.FailedRuns,
		LastRunStatus:  wf.LastRunStatus,
		CreatedAt:      wf.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:      wf.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if wf.LastRunID != nil {
		id := wf.LastRunID.String()
		resp.LastRunID = &id
	}

	if wf.LastRunAt != nil {
		ts := wf.LastRunAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastRunAt = &ts
	}

	if wf.CreatedBy != nil {
		id := wf.CreatedBy.String()
		resp.CreatedBy = &id
	}

	if len(wf.Nodes) > 0 {
		resp.Nodes = make([]NodeResponse, len(wf.Nodes))
		for i, n := range wf.Nodes {
			resp.Nodes[i] = *toNodeResponse(n)
		}
	}

	if len(wf.Edges) > 0 {
		resp.Edges = make([]EdgeResponse, len(wf.Edges))
		for i, e := range wf.Edges {
			resp.Edges[i] = *toEdgeResponse(e)
		}
	}

	return resp
}

func toNodeResponse(n *workflow.Node) *NodeResponse {
	return &NodeResponse{
		ID:          n.ID.String(),
		WorkflowID:  n.WorkflowID.String(),
		NodeKey:     n.NodeKey,
		NodeType:    string(n.NodeType),
		Name:        n.Name,
		Description: n.Description,
		UIPosition: WorkflowUIPositionResponse{
			X: n.UIPosition.X,
			Y: n.UIPosition.Y,
		},
		Config: NodeConfigResponse{
			TriggerType:        string(n.Config.TriggerType),
			TriggerConfig:      n.Config.TriggerConfig,
			ConditionExpr:      n.Config.ConditionExpr,
			ActionType:         string(n.Config.ActionType),
			ActionConfig:       n.Config.ActionConfig,
			NotificationType:   string(n.Config.NotificationType),
			NotificationConfig: n.Config.NotificationConfig,
		},
		CreatedAt: n.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func toEdgeResponse(e *workflow.Edge) *EdgeResponse {
	return &EdgeResponse{
		ID:            e.ID.String(),
		WorkflowID:    e.WorkflowID.String(),
		SourceNodeKey: e.SourceNodeKey,
		TargetNodeKey: e.TargetNodeKey,
		SourceHandle:  e.SourceHandle,
		Label:         e.Label,
		CreatedAt:     e.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func toWorkflowRunResponse(run *workflow.Run) *WorkflowRunResponse {
	resp := &WorkflowRunResponse{
		ID:             run.ID.String(),
		WorkflowID:     run.WorkflowID.String(),
		TenantID:       run.TenantID.String(),
		TriggerType:    string(run.TriggerType),
		TriggerData:    run.TriggerData,
		Status:         string(run.Status),
		TotalNodes:     run.TotalNodes,
		CompletedNodes: run.CompletedNodes,
		FailedNodes:    run.FailedNodes,
		ErrorMessage:   run.ErrorMessage,
		CreatedAt:      run.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if run.TriggeredBy != nil {
		id := run.TriggeredBy.String()
		resp.TriggeredBy = &id
	}

	if run.StartedAt != nil {
		ts := run.StartedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.StartedAt = &ts
	}

	if run.CompletedAt != nil {
		ts := run.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ts
	}

	if len(run.NodeRuns) > 0 {
		resp.NodeRuns = make([]NodeRunResponse, len(run.NodeRuns))
		for i, nr := range run.NodeRuns {
			resp.NodeRuns[i] = toNodeRunResponse(nr)
		}
	}

	return resp
}

func toNodeRunResponse(nr *workflow.NodeRun) NodeRunResponse {
	resp := NodeRunResponse{
		ID:            nr.ID.String(),
		WorkflowRunID: nr.WorkflowRunID.String(),
		NodeID:        nr.NodeID.String(),
		NodeKey:       nr.NodeKey,
		NodeType:      string(nr.NodeType),
		Status:        string(nr.Status),
		Input:         nr.Input,
		Output:        nr.Output,
		ErrorMessage:  nr.ErrorMessage,
		ErrorCode:     nr.ErrorCode,
	}

	if nr.StartedAt != nil {
		ts := nr.StartedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.StartedAt = &ts
	}

	if nr.CompletedAt != nil {
		ts := nr.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ts
	}

	return resp
}

// handleValidationError converts validation errors to API errors.
func (h *WorkflowHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

// handleServiceError converts service errors to API errors.
func (h *WorkflowHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Workflow").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Workflow already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
