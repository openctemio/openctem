package handler

import (
	"github.com/openctemio/ctis"
)

// CTISIngestRequest is a CTIS report wrapped as {"report": {...}} (the body
// of a CI run's upload, RFC-051).
type CTISIngestRequest struct {
	Report ctis.Report `json:"report"`
}
