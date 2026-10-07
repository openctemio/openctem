package handler

// The scan capability catalog over HTTP (research/27 §6.1, RFC-046 stage
// catalog): every capability with its contract (typed ports, standard
// params, required output fields, version) and its implementations, plus
// the port type set and the adapter table the workflow editor wires with.
// Static platform data: no tenant data is read or returned.

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// ScanStageImplementationResponse is one tool that runs a capability.
type ScanStageImplementationResponse struct {
	Tool    string `json:"tool"`
	Default bool   `json:"default"`
	// Batch: the tool takes a list of targets per task.
	Batch bool `json:"batch"`
	// Params maps the standard params this tool accepts to its own config
	// key.
	Params map[string]string `json:"params"`
}

// ScanStageParamResponse is one standard param of a capability.
type ScanStageParamResponse struct {
	Name        string   `json:"name"`
	Type        string   `json:"type" enums:"string,string_list,integer,boolean,port_list"`
	Description string   `json:"description"`
	Enum        []string `json:"enum,omitempty"`
	Min         *int     `json:"min,omitempty"`
	Max         *int     `json:"max,omitempty"`
}

// ScanStageResponse is one capability.
type ScanStageResponse struct {
	Key string `json:"key"`
	// ID is the versioned capability id ("scan.ports@1").
	ID          string `json:"id"`
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Available: the platform routes the capability today. A planned one
	// has a contract and no implementation yet.
	Available bool `json:"available"`
	// CrossCutting capabilities (verify.finding) are not workflow nodes.
	CrossCutting bool `json:"cross_cutting"`
	// Inputs and Outputs are stored type labels: "type" or
	// "type/sub_type" (service/http is an HTTP service).
	Inputs    []string `json:"inputs"`
	Outputs   []string `json:"outputs"`
	Relations []string `json:"relations"`
	// InPorts and OutPorts are port types (port_types[].type): an edge
	// connects an output port to an input port of the same type.
	InPorts              []string                          `json:"in_ports"`
	OutPorts             []string                          `json:"out_ports"`
	Params               []ScanStageParamResponse          `json:"params"`
	RequiredOutputFields []string                          `json:"required_output_fields"`
	Findings             bool                              `json:"findings"`
	Tier                 string                            `json:"tier" enums:"T0,T1,T2"`
	Implementations      []ScanStageImplementationResponse `json:"implementations"`
	MaxFanout            int                               `json:"max_fanout"`
	// Phase is the engagement phase of the capability (discover.passive,
	// discover.active, assess, validate, collect) and CTEMStage its CTEM
	// stage; Attack and D3FEND are the MITRE ATT&CK techniques the act
	// emulates and the D3FEND functions it performs (ctis/capability).
	Phase     string   `json:"phase,omitempty"`
	CTEMStage string   `json:"ctem_stage,omitempty"`
	Attack    []string `json:"attack,omitempty"`
	D3FEND    []string `json:"d3fend,omitempty"`
}

// ScanPortTypeResponse is one workflow port type.
type ScanPortTypeResponse struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	// Carries are the stored type labels a stream of this type holds.
	Carries []string `json:"carries"`
}

// ScanAdapterResponse is the capability that turns one port type into
// another, offered when two incompatible ports are wired.
type ScanAdapterResponse struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Capability string `json:"capability"`
}

// ScanStageListResponse is the capability catalog.
type ScanStageListResponse struct {
	Stages    []ScanStageResponse    `json:"stages"`
	PortTypes []ScanPortTypeResponse `json:"port_types"`
	Adapters  []ScanAdapterResponse  `json:"adapters"`
	// MaxHops is how many discovery hops a derived target may be from the
	// run's seeds.
	MaxHops int `json:"max_hops"`
}

// ListStages handles GET /api/v1/scans/stages
// @Summary      List scan capabilities
// @Description  The scan capability catalog: each capability with its contract (typed ports, standard params, required output fields, version), its intrusiveness tier and the tools that implement it; the port types and the adapter table.
// @Tags         Scans
// @Produce      json
// @Success      200  {object}  ScanStageListResponse
// @Security     BearerAuth
// @Router       /scans/stages [get]
func (h *ScanHandler) ListStages(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scanStageList())
}

func scanStageList() ScanStageListResponse {
	all := stage.Taxonomy()
	out := ScanStageListResponse{
		Stages:    make([]ScanStageResponse, 0, len(all)),
		PortTypes: []ScanPortTypeResponse{},
		Adapters:  []ScanAdapterResponse{},
		MaxHops:   stage.MaxHops,
	}
	for _, s := range all {
		out.Stages = append(out.Stages, scanStageResponse(s))
	}
	for _, p := range stage.PortTypes() {
		pt := ScanPortTypeResponse{Type: string(p.Type), Label: p.Label, Carries: make([]string, 0, len(p.Carries))}
		for _, c := range p.Carries {
			pt.Carries = append(pt.Carries, stage.Label(c))
		}
		out.PortTypes = append(out.PortTypes, pt)
	}
	for _, a := range stage.Adapters() {
		out.Adapters = append(out.Adapters, ScanAdapterResponse{From: string(a.From), To: string(a.To), Capability: string(a.Capability)})
	}
	return out
}

func scanStageResponse(s stage.Stage) ScanStageResponse {
	r := ScanStageResponse{
		Key: string(s.Key), ID: s.ID(), Version: s.Version,
		Name: s.Name, Description: s.Description,
		Available: s.Available(), CrossCutting: s.CrossCutting,
		Inputs: make([]string, 0, len(s.Inputs)), Outputs: make([]string, 0, len(s.Outputs)),
		Relations: append([]string{}, s.Relations...),
		InPorts:   portList(s.InPorts), OutPorts: portList(s.OutPorts),
		Params:               make([]ScanStageParamResponse, 0, len(s.Params)),
		RequiredOutputFields: append([]string{}, s.RequiredOutputFields...),
		Findings:             s.Findings,
		Tier:                 s.Tier.String(), MaxFanout: s.MaxFanout,
		Implementations: make([]ScanStageImplementationResponse, 0, len(s.Implementations)),
		Phase:           s.Phase, CTEMStage: s.CTEMStage,
		Attack: append([]string(nil), s.Attack...), D3FEND: append([]string(nil), s.D3FEND...),
	}
	for _, t := range s.Inputs {
		r.Inputs = append(r.Inputs, stage.Label(t))
	}
	for _, t := range s.Outputs {
		r.Outputs = append(r.Outputs, stage.Label(t))
	}
	for _, p := range s.Params {
		r.Params = append(r.Params, ScanStageParamResponse{
			Name: p.Name, Type: string(p.Type), Description: p.Description,
			Enum: p.Enum, Min: p.Min, Max: p.Max,
		})
	}
	for _, i := range s.Implementations {
		params := map[string]string{}
		for k, v := range i.Params {
			params[k] = v
		}
		r.Implementations = append(r.Implementations, ScanStageImplementationResponse{
			Tool: i.Tool, Default: i.Default, Batch: i.Batch, Params: params,
		})
	}
	return r
}

func portList(ps []stage.PortType) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}
