package handler

// An organization's own sensor products (docs/rfcs/RFC-037 §13): the release
// lines an organization records for sensor products it builds itself on
// sdk-go. They change only the organization's own sensor verdicts.

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CustomSensorProductResponse is one of the organization's own sensor
// products with the release line it recorded.
type CustomSensorProductResponse struct {
	// Product is the product token its sensors report.
	Product string `json:"product"`
	// LatestVersion is its newest release ("" = not set: no "update
	// available" verdict).
	LatestVersion string `json:"latest_version"`
	// MinVersion is its oldest supported release ("" = no minimum).
	MinVersion string    `json:"min_version"`
	UpdatedAt  time.Time `json:"updated_at"`
	UpdatedBy  *string   `json:"updated_by,omitempty"`
}

// CustomSensorProductListResponse lists the organization's own products.
type CustomSensorProductListResponse struct {
	Items []CustomSensorProductResponse `json:"items"`
}

// SaveCustomSensorProductRequest is the release line of one product. Both
// values are optional ("" = not set).
type SaveCustomSensorProductRequest struct {
	LatestVersion string `json:"latest_version"`
	MinVersion    string `json:"min_version"`
}

func toCustomSensorProductResponse(p sensor.CustomProduct) CustomSensorProductResponse {
	out := CustomSensorProductResponse{Product: p.Product, LatestVersion: p.Latest, MinVersion: p.Min, UpdatedAt: p.UpdatedAt}
	if p.UpdatedBy != nil {
		s := p.UpdatedBy.String()
		out.UpdatedBy = &s
	}
	return out
}

// ListCustomProducts handles GET /api/v1/sensors/custom-products
// @Summary      The organization's own sensor products
// @Description  The release lines the organization recorded for sensor products it builds itself (latest and minimum release). Its sensors of such a product get "update available" and "unsupported" verdicts from them; a product without one gets only the SDK and protocol compatibility verdicts. Only this organization's verdicts read them.
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  CustomSensorProductListResponse
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/custom-products [get]
func (h *SensorHandler) ListCustomProducts(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromContext(w, r)
	if !ok {
		return
	}
	ps, err := h.service.ListCustomProducts(r.Context(), tid)
	if err != nil {
		h.handleCustomProductError(w, err)
		return
	}
	out := CustomSensorProductListResponse{Items: make([]CustomSensorProductResponse, 0, len(ps))}
	for _, p := range ps {
		out.Items = append(out.Items, toCustomSensorProductResponse(p))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// SaveCustomProduct handles PUT /api/v1/sensors/custom-products/{product}
// @Summary      Record an own sensor product's release line
// @Description  Creates or replaces the release line of one of the organization's own sensor products. The product is the token its sensors report (lower-case letters, digits, '.', '_', '-'); names starting with openctemio- and products the platform lists are refused. Versions are vX.Y.Z or empty; the minimum may not be newer than the latest. At most 50 products. Audited.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        product  path      string                          true  "Product token"
// @Param        body     body      SaveCustomSensorProductRequest  true  "Release line"
// @Success      200      {object}  CustomSensorProductResponse
// @Failure      400      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/custom-products/{product} [put]
func (h *SensorHandler) SaveCustomProduct(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromContext(w, r)
	if !ok {
		return
	}
	var req SaveCustomSensorProductRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	p, err := h.service.SaveCustomProduct(r.Context(), sensorapp.SaveCustomProductInput{
		TenantID: tid, Product: chi.URLParam(r, "product"), Latest: req.LatestVersion, Min: req.MinVersion,
		AuditContext: h.buildAuditContext(r),
	})
	if err != nil {
		h.handleCustomProductError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toCustomSensorProductResponse(*p))
}

// DeleteCustomProduct handles DELETE /api/v1/sensors/custom-products/{product}
// @Summary      Remove an own sensor product's release line
// @Description  Its sensors get only the SDK and protocol compatibility verdicts again. Audited.
// @Tags         Sensors
// @Param        product  path  string  true  "Product token"
// @Success      204      "No Content"
// @Failure      404      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/custom-products/{product} [delete]
func (h *SensorHandler) DeleteCustomProduct(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromContext(w, r)
	if !ok {
		return
	}
	if err := h.service.DeleteCustomProduct(r.Context(), tid, chi.URLParam(r, "product"), h.buildAuditContext(r)); err != nil {
		h.handleCustomProductError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SensorHandler) handleCustomProductError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sensor.ErrCustomProductNotFound):
		apierror.NotFound("Sensor product").WriteJSON(w)
	case errors.Is(err, sensor.ErrCustomProductReserved),
		errors.Is(err, sensor.ErrCustomProductInvalid),
		errors.Is(err, sensor.ErrCustomProductLimit):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("sensor product", "error", logger.SanitizeError(err))
		h.handleServiceError(w, err)
	}
}
