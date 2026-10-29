package handler

import (
	"net/http"
	"time"

	certificateapp "github.com/openctemio/openctem/api/internal/app/certificate"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/certificate"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CertificateHandler serves the Certificates view of the external attack
// surface: certificate assets as one typed list. Every value came from a
// scan (a certificate's subject and issuer are chosen by whoever issued
// it): clients render it as text.
type CertificateHandler struct {
	svc    *certificateapp.Service
	logger *logger.Logger
}

// NewCertificateHandler creates the handler.
func NewCertificateHandler(svc *certificateapp.Service, log *logger.Logger) *CertificateHandler {
	return &CertificateHandler{svc: svc, logger: log}
}

// CertificateResponse is one certificate.
type CertificateResponse struct {
	AssetID            string     `json:"asset_id"`
	Name               string     `json:"name"`
	SubjectCN          string     `json:"subject_cn"`
	IssuerCN           string     `json:"issuer_cn"`
	IssuerOrg          string     `json:"issuer_org"`
	FingerprintSHA256  string     `json:"fingerprint_sha256"`
	SignatureAlgorithm string     `json:"signature_algorithm,omitempty"`
	NotBefore          *time.Time `json:"not_before,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	// Status is computed at read time from not_after: expired, expiring_soon
	// (within 30 days), ok, or unknown (no readable not_after).
	Status       string    `json:"status" enums:"expired,expiring_soon,ok,unknown"`
	DaysToExpiry *int      `json:"days_to_expiry,omitempty"`
	IsSelfSigned bool      `json:"is_self_signed"`
	IsWildcard   bool      `json:"is_wildcard"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// CertificateStatsResponse are the counts of one filtered set by status.
type CertificateStatsResponse struct {
	Total        int64 `json:"total"`
	Expired      int64 `json:"expired"`
	ExpiringSoon int64 `json:"expiring_soon"`
	OK           int64 `json:"ok"`
	Unknown      int64 `json:"unknown"`
}

func toCertificateResponse(c *certificate.Certificate, now time.Time) CertificateResponse {
	r := CertificateResponse{
		AssetID: c.AssetID, Name: c.Name, SubjectCN: c.SubjectCN, IssuerCN: c.IssuerCN, IssuerOrg: c.IssuerOrg,
		FingerprintSHA256: c.FingerprintSHA256, SignatureAlgorithm: c.SignatureAlg, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Status: string(certificate.StatusAt(c.NotAfter, now)), IsSelfSigned: c.IsSelfSigned, IsWildcard: c.IsWildcard,
		FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
	}
	if c.NotAfter != nil {
		d := int(c.NotAfter.Sub(now).Hours() / 24)
		r.DaysToExpiry = &d
	}
	return r
}

func certificateCaller(r *http.Request) certificateapp.Caller {
	ctx := r.Context()
	return certificateapp.Caller{
		TenantID: middleware.MustGetTenantID(ctx), UserID: middleware.GetUserID(ctx),
		IsAdmin: middleware.IsAdmin(ctx), APIKey: middleware.ReadsOnOwnScope(ctx),
	}
}

func (h *CertificateHandler) listRoute(name string) filterquery.Route {
	return filterquery.Route{Name: name, Registry: certificate.Fields,
		Options: filterspec.Options{Unknown: filterspec.UnknownStrict}, Logger: h.logger}
}

func (h *CertificateHandler) writeErr(w http.ResponseWriter, err error) {
	if _, isFilter := filterspec.AsError(err); isFilter {
		filterquery.WriteError(w, err)
		return
	}
	h.logger.Error("certificates", "error", err)
	apierror.InternalError(err).WriteJSON(w)
}

// List handles GET /api/v1/attack-surface/certificates
// @Summary      List certificates
// @Description  The certificate assets the caller may see, with the status computed from not_after. Filters follow
// @Description  the list query contract. Values are scan output: render as text.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: certificates GET /attack-surface/certificates
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  subject_cn  query  []string  false  "subject cn: any of (comma list)"  collectionFormat(csv)
// @Param  subject_cn_contains  query  string  false  "subject cn contains"
// @Param  subject_cn_not  query  []string  false  "subject cn: none of (comma list)"  collectionFormat(csv)
// @Param  issuer_cn  query  []string  false  "issuer cn: any of (comma list)"  collectionFormat(csv)
// @Param  issuer_cn_contains  query  string  false  "issuer cn contains"
// @Param  issuer_cn_not  query  []string  false  "issuer cn: none of (comma list)"  collectionFormat(csv)
// @Param  issuer_org  query  []string  false  "issuer org: any of (comma list)"  collectionFormat(csv)
// @Param  issuer_org_contains  query  string  false  "issuer org contains"
// @Param  issuer_org_not  query  []string  false  "issuer org: none of (comma list)"  collectionFormat(csv)
// @Param  fingerprint  query  []string  false  "fingerprint: any of (comma list)"  collectionFormat(csv)
// @Param  fingerprint_not  query  []string  false  "fingerprint: none of (comma list)"  collectionFormat(csv)
// @Param  status  query  []string  false  "status: any of (comma list)"  collectionFormat(csv)  Enums(expired, expiring_soon, ok, unknown)
// @Param  status_not  query  []string  false  "status: none of (comma list)"  collectionFormat(csv)  Enums(expired, expiring_soon, ok, unknown)
// @Param  not_before_gte  query  string  false  "not before at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_before_lte  query  string  false  "not before at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_before_gt  query  string  false  "not before greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_before_lt  query  string  false  "not before less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_after_gte  query  string  false  "not after at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_after_lte  query  string  false  "not after at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_after_gt  query  string  false  "not after greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_after_lt  query  string  false  "not after less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gte  query  string  false  "first seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lte  query  string  false  "first seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gt  query  string  false  "first seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lt  query  string  false  "first seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  self_signed  query  boolean  false  "self signed equals"
// @Param  wildcard  query  boolean  false  "wildcard equals"
// end filterspec-params
// @Success      200  {object}  ListResponse[CertificateResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/certificates [get]
func (h *CertificateHandler) List(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.listRoute("GET /attack-surface/certificates").ParseQuery(w, r)
	if !ok {
		return
	}
	res, err := h.svc.List(r.Context(), certificateCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	now := time.Now()
	data := make([]CertificateResponse, len(res.Data))
	for i, c := range res.Data {
		data[i] = toCertificateResponse(c, now)
	}
	writeJSON(w, http.StatusOK, ListResponse[CertificateResponse]{
		Data: data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}

// Stats handles GET /api/v1/attack-surface/certificates/stats
// @Summary      Certificate counts
// @Description  Counts by status for the same filters as the list.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: certificates GET /attack-surface/certificates/stats
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  subject_cn  query  []string  false  "subject cn: any of (comma list)"  collectionFormat(csv)
// @Param  subject_cn_contains  query  string  false  "subject cn contains"
// @Param  subject_cn_not  query  []string  false  "subject cn: none of (comma list)"  collectionFormat(csv)
// @Param  issuer_cn  query  []string  false  "issuer cn: any of (comma list)"  collectionFormat(csv)
// @Param  issuer_cn_contains  query  string  false  "issuer cn contains"
// @Param  issuer_cn_not  query  []string  false  "issuer cn: none of (comma list)"  collectionFormat(csv)
// @Param  issuer_org  query  []string  false  "issuer org: any of (comma list)"  collectionFormat(csv)
// @Param  issuer_org_contains  query  string  false  "issuer org contains"
// @Param  issuer_org_not  query  []string  false  "issuer org: none of (comma list)"  collectionFormat(csv)
// @Param  fingerprint  query  []string  false  "fingerprint: any of (comma list)"  collectionFormat(csv)
// @Param  fingerprint_not  query  []string  false  "fingerprint: none of (comma list)"  collectionFormat(csv)
// @Param  status  query  []string  false  "status: any of (comma list)"  collectionFormat(csv)  Enums(expired, expiring_soon, ok, unknown)
// @Param  status_not  query  []string  false  "status: none of (comma list)"  collectionFormat(csv)  Enums(expired, expiring_soon, ok, unknown)
// @Param  not_before_gte  query  string  false  "not before at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_before_lte  query  string  false  "not before at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_before_gt  query  string  false  "not before greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_before_lt  query  string  false  "not before less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_after_gte  query  string  false  "not after at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_after_lte  query  string  false  "not after at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_after_gt  query  string  false  "not after greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  not_after_lt  query  string  false  "not after less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gte  query  string  false  "first seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lte  query  string  false  "first seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gt  query  string  false  "first seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lt  query  string  false  "first seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  self_signed  query  boolean  false  "self signed equals"
// @Param  wildcard  query  boolean  false  "wildcard equals"
// end filterspec-params
// @Success      200  {object}  CertificateStatsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/certificates/stats [get]
func (h *CertificateHandler) Stats(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.listRoute("GET /attack-surface/certificates/stats").ParseQuery(w, r)
	if !ok {
		return
	}
	st, err := h.svc.Stats(r.Context(), certificateCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, CertificateStatsResponse(*st))
}
