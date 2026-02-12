package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the admin API HTTP client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	verbose    bool
}

// NewClient creates a new admin API client.
func NewClient(baseURL, apiKey string, verbose bool) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		verbose: verbose,
	}
}

// Do performs an HTTP request and returns the response body.
func (c *Client) Do(method, path string, body any) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(context.Background(), method, url, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-Admin-API-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if c.verbose {
		fmt.Printf(">>> %s %s\n", method, url)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	if c.verbose {
		fmt.Printf("<<< %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode, parseAPIError(resp.StatusCode, respBody)
	}

	return respBody, resp.StatusCode, nil
}

// Get performs a GET request.
func (c *Client) Get(path string) ([]byte, error) {
	data, _, err := c.Do(http.MethodGet, path, nil)
	return data, err
}

// Post performs a POST request.
func (c *Client) Post(path string, body any) ([]byte, error) {
	data, _, err := c.Do(http.MethodPost, path, body)
	return data, err
}

// Patch performs a PATCH request.
func (c *Client) Patch(path string, body any) ([]byte, error) {
	data, _, err := c.Do(http.MethodPatch, path, body)
	return data, err
}

// Delete performs a DELETE request.
func (c *Client) Delete(path string) error {
	_, _, err := c.Do(http.MethodDelete, path, nil)
	return err
}

// APIError represents an error from the admin API.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("API error: %d %s", e.StatusCode, http.StatusText(e.StatusCode))
}

func parseAPIError(statusCode int, body []byte) error {
	apiErr := &APIError{StatusCode: statusCode}

	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Error.Message != "" {
			apiErr.Code = parsed.Error.Code
			apiErr.Message = parsed.Error.Message
		} else if parsed.Message != "" {
			apiErr.Message = parsed.Message
		}
	}

	if apiErr.Message == "" {
		switch statusCode {
		case 401:
			apiErr.Message = "unauthorized: invalid or missing API key"
		case 403:
			apiErr.Message = "forbidden: insufficient permissions"
		case 404:
			apiErr.Message = "resource not found"
		case 409:
			apiErr.Message = "conflict: resource already exists"
		default:
			apiErr.Message = fmt.Sprintf("API error: %d %s", statusCode, http.StatusText(statusCode))
		}
	}

	return apiErr
}

// Response types matching server handler structs.

type ValidateResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

type AdminResponse struct {
	ID         string  `json:"id"`
	Email      string  `json:"email"`
	Name       string  `json:"name"`
	Role       string  `json:"role"`
	IsActive   bool    `json:"is_active"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	LastUsedIP string  `json:"last_used_ip,omitempty"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
}

type AdminListResponse struct {
	Data       []AdminResponse `json:"data"`
	Total      int64           `json:"total"`
	Page       int             `json:"page"`
	PerPage    int             `json:"per_page"`
	TotalPages int             `json:"total_pages"`
}

type AdminCreateResponse struct {
	Admin  AdminResponse `json:"admin"`
	APIKey string        `json:"api_key"`
}

type AdminRotateKeyResponse struct {
	APIKey string `json:"api_key"`
}

type AuditLogResponse struct {
	ID             string         `json:"id"`
	AdminID        *string        `json:"admin_id,omitempty"`
	AdminEmail     string         `json:"admin_email"`
	Action         string         `json:"action"`
	ResourceType   string         `json:"resource_type,omitempty"`
	ResourceID     *string        `json:"resource_id,omitempty"`
	ResourceName   string         `json:"resource_name,omitempty"`
	RequestMethod  string         `json:"request_method,omitempty"`
	RequestPath    string         `json:"request_path,omitempty"`
	ResponseStatus int            `json:"response_status,omitempty"`
	RequestBody    map[string]any `json:"request_body,omitempty"`
	IPAddress      string         `json:"ip_address,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
	Success        bool           `json:"success"`
	ErrorMessage   string         `json:"error_message,omitempty"`
	CreatedAt      string         `json:"created_at"`
}

type AuditLogListResponse struct {
	Data       []AuditLogResponse `json:"data"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PerPage    int                `json:"per_page"`
	TotalPages int                `json:"total_pages"`
}

type AuditStatsResponse struct {
	Total         int64              `json:"total"`
	Failed24h     int64              `json:"failed_24h"`
	RecentActions []AuditLogResponse `json:"recent_actions"`
}

type TargetMappingResponse struct {
	ID          string  `json:"id"`
	TargetType  string  `json:"target_type"`
	AssetType   string  `json:"asset_type"`
	Priority    int     `json:"priority"`
	IsActive    bool    `json:"is_active"`
	IsPrimary   bool    `json:"is_primary"`
	Description *string `json:"description,omitempty"`
	CreatedBy   *string `json:"created_by,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

type TargetMappingListResponse struct {
	Data       []TargetMappingResponse `json:"data"`
	Total      int64                   `json:"total"`
	Page       int                     `json:"page"`
	PerPage    int                     `json:"per_page"`
	TotalPages int                     `json:"total_pages"`
}
