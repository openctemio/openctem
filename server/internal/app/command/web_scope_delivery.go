package command

// The deny list a sensor is sent (docs/architecture/web-discovery.md): a web
// scope is stored with its deny paths in the cut form every sensor holds
// (a "*" segment cut to the path before it: "/tenants/*/admin" is
// "/tenants/") and, beside it, the form as written (deny_paths_wildcard,
// the platform's own key). At claim a sensor that reads "*" segments
// (sensordom.ReadsWildcardDenyPaths) gets the written form as its deny_paths,
// so an exclusion on one path under a wildcard does not block the whole
// origin; every other sensor gets the cut form. The platform-only key never
// leaves the platform.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const keyDenyWildcard = "deny_paths_wildcard"

// sensorReadsWildcard says whether the sensor that claims c reads "*" deny
// path segments. A shared sensor, an unreadable sensor and a sensor that
// reported no release version are older: they get the cut form.
func (s *Service) sensorReadsWildcard(ctx context.Context, c *commanddom.Command, sensorID string) bool {
	if c.IsPlatformJob || s.sensors == nil {
		return false
	}
	id, err := shared.IDFromString(sensorID)
	if err != nil {
		return false
	}
	sen, err := s.sensors.GetByTenantAndID(ctx, c.TenantID, id)
	if err != nil || sen == nil {
		return false
	}
	return sensordom.ReadsWildcardDenyPaths(sen.Version)
}

// webScopeDelivery returns payload with the platform-only key removed from
// its web scope and, when wildcard, its deny paths replaced by the written
// form. A payload without the key is returned as it is. A web scope it cannot
// read is an error: the job is not handed out.
func webScopeDelivery(payload json.RawMessage, wildcard bool) (json.RawMessage, error) {
	if !bytes.Contains(payload, []byte(`"`+keyDenyWildcard+`"`)) {
		return payload, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("web scope payload: %w", err)
	}
	var ws map[string]json.RawMessage
	if err := json.Unmarshal(fields[commanddom.PayloadKeyWebScope], &ws); err != nil {
		return nil, fmt.Errorf("web scope: %w", err)
	}
	full, ok := ws[keyDenyWildcard]
	delete(ws, keyDenyWildcard)
	if ok && wildcard {
		var list []string
		if err := json.Unmarshal(full, &list); err != nil {
			return nil, fmt.Errorf("web scope deny paths: %w", err)
		}
		ws["deny_paths"] = full
	}
	rawWS, err := json.Marshal(ws)
	if err != nil {
		return nil, err
	}
	fields[commanddom.PayloadKeyWebScope] = rawWS
	return json.Marshal(fields)
}
