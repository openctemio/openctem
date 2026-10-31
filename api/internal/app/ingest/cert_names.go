package ingest

// Certificate names as a discovery source (research/333 D5): the subject
// alternative names (and the subject CN) of every TLS certificate a report
// puts in the inventory are handed to a promoter, which proposes the names
// below one of the tenant's domain roots as candidate subdomains with
// attribution evidence. Every producer that reports certificates (httpx,
// tlsx, nuclei, uploads) feeds it the same way. Design and rules:
// docs/architecture/easm.md ("Certificate SAN promotion").

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// maxCertificatesPerReport bounds the certificates of one report
	// handed to the promoter.
	maxCertificatesPerReport = 1000
	// maxNamesPerCertificate bounds the names read from one certificate.
	maxNamesPerCertificate = 100
)

// CertificateNames is one certificate asset an ingest wrote, with the names
// it carries as the report stated them (untrusted: the promoter
// normalizes and filters them).
type CertificateNames struct {
	// AssetID is the persisted certificate asset (this tenant's).
	AssetID shared.ID
	// Name is the certificate asset's name (its fingerprint, usually).
	Name string
	// Names are the subject CN and the SANs, at most maxNamesPerCertificate.
	Names     []string
	Issuer    string
	NotBefore *time.Time
	NotAfter  *time.Time
}

// CertificateNamePromoter proposes the names of certificates as candidate
// assets of the tenant (*certmonitor.Service). tool is the report's tool.
type CertificateNamePromoter interface {
	PromoteCertificateNames(ctx context.Context, tenantID shared.ID, tool string, certs []CertificateNames) (int, error)
}

// SetCertificateNamePromoter wires certificate SAN promotion (nil: off).
func (s *Service) SetCertificateNamePromoter(p CertificateNamePromoter) { s.certNames = p }

// promoteCertificateNames hands the certificates this report wrote to the
// promoter. Best-effort: the assets are stored, so a failure is logged and
// never fails the ingest. A CI run's report (one repository) is not an
// attack-surface source.
func (s *Service) promoteCertificateNames(ctx context.Context, tenantID shared.ID, binding Binding, report *ctis.Report, assetMap map[string]shared.ID) {
	if s.certNames == nil || binding.Kind == BindingCIRun || report == nil {
		return
	}
	certs := reportCertificateNames(report, assetMap)
	if len(certs) == 0 {
		return
	}
	tool := ""
	if report.Tool != nil {
		tool = report.Tool.Name
	}
	n, err := s.certNames.PromoteCertificateNames(ctx, tenantID, tool, certs)
	if err != nil {
		s.logger.Warn("certificate SAN promotion failed", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	if n > 0 {
		s.logger.Info("certificate SAN promotion", "tenant_id", tenantID.String(), "assets_created", n)
	}
}

// reportCertificateNames collects the report's certificate assets that this
// ingest persisted (present in assetMap: written in this tenant, not
// refused or excluded) with their names, from the technical block and the
// flat properties alike.
func reportCertificateNames(report *ctis.Report, assetMap map[string]shared.ID) []CertificateNames {
	out := make([]CertificateNames, 0, min(len(report.Assets), maxCertificatesPerReport))
	seen := map[shared.ID]bool{}
	for i := range report.Assets {
		a := &report.Assets[i]
		if a.Type != ctis.AssetTypeCertificate {
			continue
		}
		id, ok := assetMap[a.ID]
		if !ok || id.IsZero() || seen[id] {
			continue
		}
		c := CertificateNames{AssetID: id, Name: getAssetName(a)}
		var raw []string
		if t := a.Technical; t != nil && t.Certificate != nil {
			cert := t.Certificate
			raw = append(raw, cert.SubjectCN)
			raw = append(raw, cert.SANs...)
			c.Issuer = firstNonEmptyStr(cert.IssuerOrg, cert.IssuerCN)
			c.NotBefore, c.NotAfter = cert.NotBefore, cert.NotAfter
		}
		raw = append(raw, propString(a.Properties, "subject_cn"))
		raw = append(raw, propStrings(a.Properties["sans"])...)
		if c.Issuer == "" {
			c.Issuer = firstNonEmptyStr(propString(a.Properties, "issuer_org"), propString(a.Properties, "issuer_cn"))
		}
		if c.NotAfter == nil {
			c.NotAfter = propTime(a.Properties, "not_after")
		}
		if c.NotBefore == nil {
			c.NotBefore = propTime(a.Properties, "not_before")
		}
		dup := map[string]bool{}
		for _, n := range raw {
			n = strings.TrimSpace(n)
			if n == "" || dup[n] {
				continue
			}
			dup[n] = true
			c.Names = append(c.Names, n)
			if len(c.Names) == maxNamesPerCertificate {
				break
			}
		}
		if len(c.Names) == 0 {
			continue
		}
		seen[id] = true
		out = append(out, c)
		if len(out) == maxCertificatesPerReport {
			break
		}
	}
	return out
}

func propString(props ctis.Properties, key string) string {
	s, _ := props[key].(string)
	return s
}

func propTime(props ctis.Properties, key string) *time.Time {
	s := propString(props, key)
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
