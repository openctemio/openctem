package scm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GitLabClient implements the Client interface for GitLab
type GitLabClient struct {
	config     Config
	httpClient *http.Client
	baseURL    string
}

// NewGitLabClient creates a new GitLab client
func NewGitLabClient(config Config) (*GitLabClient, error) {
	baseURL := "https://gitlab.com/api/v4"
	if config.BaseURL != "" && config.BaseURL != defaultGitLabURL {
		// For self-hosted GitLab, construct the API URL
		baseURL = strings.TrimSuffix(config.BaseURL, "/") + "/api/v4"
	}

	return &GitLabClient{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    baseURL,
	}, nil
}

// TestConnection verifies the connection and returns user/org info
func (c *GitLabClient) TestConnection(ctx context.Context) (*ConnectionTestResult, error) {
	result := &ConnectionTestResult{Success: false}

	// Get authenticated user
	user, err := c.GetUser(ctx)
	if err != nil {
		result.Message = fmt.Sprintf("Authentication failed: %v", err)
		return result, nil
	}
	result.User = user

	// Verify organization access if specified
	if c.config.Organization != "" {
		if err := c.verifyOrganizationAccess(ctx, result, user); err != nil {
			return result, err
		}
	} else {
		// Count all user repositories (personal + groups)
		repoCount, err := c.countUserProjects(ctx)
		if err == nil {
			result.RepoCount = repoCount
		}
	}

	result.Success = true
	result.Message = connectionSuccessful
	return result, nil
}

// verifyOrganizationAccess verifies access to the configured organization and populates result.
func (c *GitLabClient) verifyOrganizationAccess(ctx context.Context, result *ConnectionTestResult, user *User) error {
	// Check if organization matches current user - show all repos
	if user.Username == c.config.Organization {
		return c.setUserAsOrganization(ctx, result, user)
	}

	// Try as a group first, then fall back to user namespace
	return c.resolveGroupOrUserNamespace(ctx, result)
}

// setUserAsOrganization sets the current user as the organization in the result.
func (c *GitLabClient) setUserAsOrganization(ctx context.Context, result *ConnectionTestResult, user *User) error {
	repoCount, err := c.countUserProjects(ctx)
	if err == nil {
		result.RepoCount = repoCount
	}
	result.Organization = &Organization{
		ID:        user.ID,
		Name:      user.Username,
		AvatarURL: user.AvatarURL,
		RepoCount: result.RepoCount,
	}
	return nil
}

// resolveGroupOrUserNamespace tries to resolve the organization as a group, falling back to user namespace.
func (c *GitLabClient) resolveGroupOrUserNamespace(ctx context.Context, result *ConnectionTestResult) error {
	group, err := c.getGroup(ctx, c.config.Organization)
	if err == nil {
		result.Organization = group
		result.RepoCount = group.RepoCount
		return nil
	}

	// If not found as group, try as a user namespace
	userNS, userErr := c.getUserNamespace(ctx, c.config.Organization)
	if userErr != nil {
		result.Message = fmt.Sprintf("Cannot access group or user '%s': %v", c.config.Organization, err)
		return err
	}

	result.Organization = userNS
	result.RepoCount = userNS.RepoCount
	return nil
}

// countUserProjects counts all projects the user has access to (lightweight - only fetches count)
func (c *GitLabClient) countUserProjects(ctx context.Context) (int, error) {
	path := "/projects?per_page=1&membership=true"
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Get total from headers
	if totalStr := resp.Header.Get("X-Total"); totalStr != "" {
		if parsedTotal, err := strconv.Atoi(totalStr); err == nil {
			return parsedTotal, nil
		}
	}

	return 0, nil
}

// GetUser returns the authenticated user
func (c *GitLabClient) GetUser(ctx context.Context) (*User, error) {
	resp, err := c.doRequest(ctx, "GET", "/user", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuthFailed.Wrap(fmt.Errorf("invalid or expired token"))
	}

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Limit response body to 1MB to prevent memory exhaustion
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body))
	}

	var glUser struct {
		ID        int    `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&glUser); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &User{
		ID:        strconv.Itoa(glUser.ID),
		Username:  glUser.Username,
		Name:      glUser.Name,
		Email:     glUser.Email,
		AvatarURL: glUser.AvatarURL,
	}, nil
}

// ListOrganizations returns groups the user has access to
func (c *GitLabClient) ListOrganizations(ctx context.Context, opts ListOptions) ([]Organization, error) {
	if opts.PerPage == 0 {
		opts.PerPage = 20
	}
	if opts.Page == 0 {
		opts.Page = 1
	}

	// List groups the user is a member of
	path := fmt.Sprintf("/groups?page=%d&per_page=%d&min_access_level=10&order_by=name&sort=asc",
		opts.Page, opts.PerPage)

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var glGroups []struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		FullPath    string `json:"full_path"`
		Description string `json:"description"`
		AvatarURL   string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&glGroups); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	orgs := make([]Organization, len(glGroups))
	for i, g := range glGroups {
		orgs[i] = Organization{
			ID:          strconv.Itoa(g.ID),
			Name:        g.FullPath, // Use full_path for nested groups
			Description: g.Description,
			AvatarURL:   g.AvatarURL,
		}
	}

	return orgs, nil
}

// ListRepositories returns projects accessible to the user
func (c *GitLabClient) ListRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	if opts.PerPage == 0 {
		opts.PerPage = 20
	}
	if opts.Page == 0 {
		opts.Page = 1
	}

	// Try organization-specific path first
	if c.config.Organization != "" {
		return c.listOrganizationRepositories(ctx, opts)
	}

	// List all projects user has access to (personal + groups)
	return c.listAllUserRepositories(ctx, opts)
}

// listOrganizationRepositories lists repositories for a specific organization/user.
func (c *GitLabClient) listOrganizationRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	// Check if organization matches authenticated user - if so, show all repos
	currentUser, _ := c.GetUser(ctx)
	if currentUser != nil && currentUser.Username == c.config.Organization {
		return c.listAllUserRepositories(ctx, opts)
	}

	// Try group endpoint first
	result, err := c.tryListGroupRepositories(ctx, opts)
	if err == nil {
		return result, nil
	}

	// Fall back to user namespace
	return c.listUserNamespaceRepositories(ctx, opts)
}

// listAllUserRepositories lists all projects the user has access to.
func (c *GitLabClient) listAllUserRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	path := fmt.Sprintf("/projects?page=%d&per_page=%d&membership=true&order_by=updated_at&sort=desc",
		opts.Page, opts.PerPage)
	if opts.Search != "" {
		path += "&search=" + url.QueryEscape(opts.Search)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	return c.parseProjectsResponse(resp)
}

// tryListGroupRepositories attempts to list repositories from a group.
func (c *GitLabClient) tryListGroupRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	groupPath := fmt.Sprintf("/groups/%s/projects?page=%d&per_page=%d&include_subgroups=true&order_by=updated_at&sort=desc&with_shared=false",
		url.PathEscape(c.config.Organization), opts.Page, opts.PerPage)
	if opts.Search != "" {
		groupPath += "&search=" + url.QueryEscape(opts.Search)
	}

	resp, err := c.doRequest(ctx, "GET", groupPath, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("group not found or not accessible")
	}
	return c.parseProjectsResponse(resp)
}

// listUserNamespaceRepositories lists repositories from a user namespace.
func (c *GitLabClient) listUserNamespaceRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	path := fmt.Sprintf("/users/%s/projects?page=%d&per_page=%d&order_by=updated_at&sort=desc",
		url.PathEscape(c.config.Organization), opts.Page, opts.PerPage)
	if opts.Search != "" {
		path += "&search=" + url.QueryEscape(opts.Search)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	return c.parseProjectsResponse(resp)
}

// parseProjectsResponse parses the GitLab projects API response
func (c *GitLabClient) parseProjectsResponse(resp *http.Response) (*ListResult, error) {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Limit response body to 1MB to prevent memory exhaustion
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body))
	}

	var glProjects []glProject
	if err := json.NewDecoder(resp.Body).Decode(&glProjects); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	repos := convertGLProjects(glProjects, c.getBaseWebURL())

	// Get total from headers
	total := len(repos)
	if totalStr := resp.Header.Get("X-Total"); totalStr != "" {
		if parsedTotal, err := strconv.Atoi(totalStr); err == nil {
			total = parsedTotal
		}
	}

	// Check if there are more pages
	hasMore := false
	nextPage := 0
	if nextPageStr := resp.Header.Get("X-Next-Page"); nextPageStr != "" {
		if parsedNextPage, err := strconv.Atoi(nextPageStr); err == nil && parsedNextPage > 0 {
			hasMore = true
			nextPage = parsedNextPage
		}
	}

	return &ListResult{
		Repositories: repos,
		Total:        total,
		HasMore:      hasMore,
		NextPage:     nextPage,
	}, nil
}

// GetRepository returns a single project by full path (namespace/project)
func (c *GitLabClient) GetRepository(ctx context.Context, fullName string) (*Repository, error) {
	// GitLab expects URL-encoded path
	encodedPath := url.PathEscape(fullName)
	path := fmt.Sprintf("/projects/%s", encodedPath)

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("project %s not found", fullName))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var projectData glProject
	if err := json.NewDecoder(resp.Body).Decode(&projectData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	repos := convertGLProjects([]glProject{projectData}, c.getBaseWebURL())
	if len(repos) == 0 {
		return nil, ErrNotFound
	}

	repo := repos[0]

	// Fetch languages for this project
	languages, err := c.getProjectLanguages(ctx, fullName)
	if err == nil && languages != nil {
		repo.Languages = languages
	}

	return &repo, nil
}

// getProjectLanguages fetches all languages for a project
func (c *GitLabClient) getProjectLanguages(ctx context.Context, fullName string) (map[string]int, error) {
	encodedPath := url.PathEscape(fullName)
	path := fmt.Sprintf("/projects/%s/languages", encodedPath)

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// GitLab returns languages as {"Go": 45.5, "JavaScript": 30.2} (percentages)
	var languagePercentages map[string]float64
	if err := json.NewDecoder(resp.Body).Decode(&languagePercentages); err != nil {
		return nil, fmt.Errorf("failed to decode languages: %w", err)
	}

	// Convert percentages to approximate byte counts (multiply by 100 for relative values)
	languages := make(map[string]int)
	for lang, pct := range languagePercentages {
		languages[lang] = int(pct * 100)
	}

	return languages, nil
}

// getGroup retrieves a group by path
func (c *GitLabClient) getGroup(ctx context.Context, path string) (*Organization, error) {
	encodedPath := url.PathEscape(path)
	apiPath := fmt.Sprintf("/groups/%s", encodedPath)

	resp, err := c.doRequest(ctx, "GET", apiPath, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("group %s not found", path))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var glGroup struct {
		ID           int    `json:"id"`
		Name         string `json:"name"`
		FullPath     string `json:"full_path"`
		Description  string `json:"description"`
		AvatarURL    string `json:"avatar_url"`
		ProjectCount int    `json:"projects_count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&glGroup); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &Organization{
		ID:          strconv.Itoa(glGroup.ID),
		Name:        glGroup.FullPath,
		Description: glGroup.Description,
		AvatarURL:   glGroup.AvatarURL,
		RepoCount:   glGroup.ProjectCount,
	}, nil
}

// getUserNamespace retrieves a user namespace (for user's personal projects)
func (c *GitLabClient) getUserNamespace(ctx context.Context, username string) (*Organization, error) {
	// Get user info
	apiPath := fmt.Sprintf("/users?username=%s", url.QueryEscape(username))

	resp, err := c.doRequest(ctx, "GET", apiPath, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var users []struct {
		ID        int    `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(users) == 0 {
		return nil, ErrNotFound.Wrap(fmt.Errorf("user %s not found", username))
	}

	user := users[0]

	// Get project count for this user
	projectPath := fmt.Sprintf("/users/%d/projects?per_page=1", user.ID)
	projectResp, err := c.doRequest(ctx, "GET", projectPath, nil)
	if err != nil {
		return nil, err
	}
	defer projectResp.Body.Close()

	projectCount := 0
	if totalStr := projectResp.Header.Get("X-Total"); totalStr != "" {
		if parsedTotal, err := strconv.Atoi(totalStr); err == nil {
			projectCount = parsedTotal
		}
	}

	return &Organization{
		ID:          strconv.Itoa(user.ID),
		Name:        user.Username,
		Description: user.Name,
		AvatarURL:   user.AvatarURL,
		RepoCount:   projectCount,
	}, nil
}

// doRequest performs an HTTP request with authentication
func (c *GitLabClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PRIVATE-TOKEN", c.config.AccessToken)
	req.Header.Set("User-Agent", defaultUserAgent)

	return c.httpClient.Do(req)
}

// getBaseWebURL returns the base web URL for GitLab
func (c *GitLabClient) getBaseWebURL() string {
	if c.config.BaseURL != "" && c.config.BaseURL != defaultGitLabURL {
		return strings.TrimSuffix(c.config.BaseURL, "/")
	}
	return defaultGitLabURL
}

// glProject is the GitLab API project response structure
type glProject struct {
	ID                int       `json:"id"`
	Name              string    `json:"name"`
	Path              string    `json:"path"`
	PathWithNamespace string    `json:"path_with_namespace"`
	Description       string    `json:"description"`
	WebURL            string    `json:"web_url"`
	HTTPURLToRepo     string    `json:"http_url_to_repo"`
	SSHURLToRepo      string    `json:"ssh_url_to_repo"`
	DefaultBranch     string    `json:"default_branch"`
	Visibility        string    `json:"visibility"` // private, internal, public
	Archived          bool      `json:"archived"`
	ForkedFromProject *struct{} `json:"forked_from_project"`
	Topics            []string  `json:"topics"`
	StarCount         int       `json:"star_count"`
	ForksCount        int       `json:"forks_count"`
	CreatedAt         time.Time `json:"created_at"`
	LastActivityAt    time.Time `json:"last_activity_at"`
}

func convertGLProjects(glProjects []glProject, baseWebURL string) []Repository {
	repos := make([]Repository, len(glProjects))
	for i, p := range glProjects {
		webURL := p.WebURL
		if webURL == "" {
			webURL = fmt.Sprintf("%s/%s", baseWebURL, p.PathWithNamespace)
		}

		repos[i] = Repository{
			ID:            strconv.Itoa(p.ID),
			Name:          p.Name,
			FullName:      p.PathWithNamespace,
			Description:   p.Description,
			HTMLURL:       webURL,
			CloneURL:      p.HTTPURLToRepo,
			SSHURL:        p.SSHURLToRepo,
			DefaultBranch: p.DefaultBranch,
			IsPrivate:     p.Visibility != "public",
			IsFork:        p.ForkedFromProject != nil,
			IsArchived:    p.Archived,
			Topics:        p.Topics,
			Stars:         p.StarCount,
			Forks:         p.ForksCount,
			CreatedAt:     p.CreatedAt,
			UpdatedAt:     p.LastActivityAt,
		}
	}
	return repos
}
