package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/notifymsg"
)

// NotificationPreviewRequest is the channel message to preview: the detail
// level, the template being written and the kind of event to show.
type NotificationPreviewRequest struct {
	DetailLevel     string `json:"detail_level" validate:"omitempty,oneof=minimal standard full"`
	MessageTemplate string `json:"message_template" validate:"max=8000"`
	// EventType is the event to render; unknown types render as a generic
	// event. Default new_exposure.
	EventType string `json:"event_type" validate:"max=100"`
	// Locale is en or vi (default en).
	Locale string `json:"locale" validate:"max=16"`
}

// NotificationPreviewLine is one line of the previewed message.
type NotificationPreviewLine struct {
	Label string `json:"label,omitempty"`
	Value string `json:"value"`
}

// NotificationPreviewResponse is the previewed message, rendered by the
// same card model every channel uses.
type NotificationPreviewResponse struct {
	Headline    string                    `json:"headline"`
	Severity    string                    `json:"severity"`
	Lines       []NotificationPreviewLine `json:"lines"`
	ActionLabel string                    `json:"action_label"`
	Text        string                    `json:"text"`
	// Variables lists the template variables a template may use.
	Variables []string `json:"variables"`
}

// PreviewNotification handles POST /api/v1/integrations/notifications/preview
// @Summary      Preview a notification message
// @Description  Renders a channel message from sample data with the given detail level and template. Reads no organization data. A template with an unknown variable or a stray brace is refused with 400, as on save.
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        request  body      NotificationPreviewRequest  true  "Message settings"
// @Success      200      {object}  NotificationPreviewResponse
// @Failure      400      {object}  map[string]string  "Invalid template or detail level"
// @Failure      401      {object}  map[string]string  "Unauthorized"
// @Failure      403      {object}  map[string]string  "Forbidden"
// @Security     BearerAuth
// @Router       /integrations/notifications/preview [post]
func (h *IntegrationHandler) PreviewNotification(w http.ResponseWriter, r *http.Request) {
	var req NotificationPreviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	resp, err := previewNotification(req)
	if err != nil {
		apierror.BadRequest(notifymsg.ValidationMessage(err)).WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// previewNotification renders the sample event. Its errors are template
// validation messages (ours, naming the template's own variables).
func previewNotification(req NotificationPreviewRequest) (NotificationPreviewResponse, error) {
	level := notifymsg.DefaultLevel
	if req.DetailLevel != "" {
		l, err := notifymsg.ParseLevel(req.DetailLevel)
		if err != nil {
			return NotificationPreviewResponse{}, err
		}
		level = l
	}
	if err := notifymsg.ValidateTemplate(req.MessageTemplate); err != nil {
		return NotificationPreviewResponse{}, err
	}
	eventType := strings.TrimSpace(req.EventType)
	if eventType == "" {
		eventType = "new_exposure"
	}
	card := notifymsg.Build(notifymsg.SampleInput(eventType, level, req.Locale, "https://console.example.com"))
	card, _ = notifymsg.ApplyTemplate(card, req.MessageTemplate)
	resp := NotificationPreviewResponse{
		Headline: card.Headline, Severity: card.Severity, ActionLabel: card.Action.Label, Text: card.Text(),
		Lines: []NotificationPreviewLine{},
	}
	for _, l := range card.Lines() {
		resp.Lines = append(resp.Lines, NotificationPreviewLine{Label: l.Label, Value: l.Value})
	}
	for _, v := range notifymsg.Vars() {
		resp.Variables = append(resp.Variables, string(v))
	}
	return resp, nil
}
