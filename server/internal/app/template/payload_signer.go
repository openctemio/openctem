package template

// Signing the custom templates of a command as it leaves for a sensor.
// Design and threat model: docs/rfcs/RFC-038-sensor-tool-settings.md,
// "Custom template trust".

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// envelopeKey is the payload key of the signed manifest (sdk-go
// ScanCommandPayload.CustomTemplatesEnvelope).
const envelopeKey = "custom_templates_envelope"

// PayloadSigner signs the custom templates of a command payload as one
// manifest, bound to the command's tenant, the sensor that polled it and
// the command, after validating every template again with the validator
// uploads go through. If any template fails validation (or cannot be read),
// the set is sent without a manifest, so the sensor refuses the whole
// command: only sets this validator accepted ever carry a signature.
type PayloadSigner struct {
	keys   *scannertemplate.Keyring
	logger *logger.Logger
	now    func() time.Time
}

// NewPayloadSigner returns a signer using keys.
func NewPayloadSigner(keys *scannertemplate.Keyring, log *logger.Logger) *PayloadSigner {
	return &PayloadSigner{keys: keys, logger: log.With("component", "template_signer"), now: time.Now}
}

// SignTemplates returns payload with a signed manifest of its
// custom_templates for tenantID, sensorID and commandID (the platform's own
// values, never ones from the payload). Whatever custom_templates_envelope
// the payload brought is dropped. A payload without custom templates is
// returned as is.
func (p *PayloadSigner) SignTemplates(tenantID, sensorID, commandID string, payload json.RawMessage) json.RawMessage {
	if p == nil || len(payload) == 0 || !bytes.Contains(payload, []byte(`"custom_templates`)) {
		return payload
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(payload, &doc); err != nil {
		p.logger.Warn("command payload with custom templates is not a JSON object; templates sent unsigned",
			"command_id", commandID, "error", err)
		return payload
	}
	_, hadEnvelope := doc[envelopeKey]
	delete(doc, envelopeKey)
	unsigned := func() json.RawMessage {
		if !hadEnvelope {
			return payload
		}
		out, err := json.Marshal(doc)
		if err != nil {
			return payload
		}
		return out
	}

	var templates []struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		TemplateType string `json:"template_type"`
		Content      string `json:"content"`
	}
	if raw, ok := doc["custom_templates"]; !ok || json.Unmarshal(raw, &templates) != nil || len(templates) == 0 {
		return unsigned()
	}

	now := p.now().UTC()
	m := scannertemplate.Manifest{
		Kind: scannertemplate.ManifestKind, TenantID: tenantID, SensorID: sensorID, CommandID: commandID,
		IssuedAt: now, ExpiresAt: now.Add(scannertemplate.ManifestTTL),
		Templates: make([]scannertemplate.ManifestTemplate, 0, len(templates)),
	}
	for i, t := range templates {
		content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(t.Content))
		if err != nil {
			p.logger.Warn("custom template content is not base64; set sent unsigned",
				"command_id", commandID, "template", t.Name, "index", i)
			return unsigned()
		}
		if res := ValidateTemplate(scannertemplate.TemplateType(t.TemplateType), content); res == nil || !res.Valid || res.HasErrors() {
			msg := ""
			if res != nil {
				msg = res.ErrorMessages()
			}
			p.logger.Warn("custom template fails validation; set sent unsigned, the sensor will refuse it",
				"command_id", commandID, "template", t.Name, "index", i, "errors", msg)
			return unsigned()
		}
		m.Templates = append(m.Templates, scannertemplate.NewManifestTemplate(t.ID, t.Name, t.TemplateType, content))
	}
	env, err := p.keys.Seal(m)
	if err != nil {
		p.logger.Warn("custom templates could not be signed; sent unsigned", "command_id", commandID, "error", err)
		return unsigned()
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return unsigned()
	}
	doc[envelopeKey] = raw
	out, err := json.Marshal(doc)
	if err != nil {
		return unsigned()
	}
	return out
}
