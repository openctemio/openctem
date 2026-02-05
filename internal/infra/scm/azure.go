package scm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const azureDefaultBranchPrefix = "refs/heads/"

// AzureClient implements the Client interface for Azure DevOps
// Supports both Azure DevOps Services (dev.azure.com) and Azure DevOps Server
type AzureClient struct {
	config     Config
	httpClient *http.Client
	baseURL    string
	isCloud    bool
}

// NewAzureClient creates a new Azure DevOps client
func NewAzureClient(config Config) (*AzureClient, error) {
	// Default to Azure DevOps Services
	baseURL := "https://dev.azure.com"
	isCloud := true

	if config.BaseURL != "" &&
		config.BaseURL != "https://dev.azure.com" &&
		config.BaseURL != "https://azure.microsoft.com" {
		// For Azure DevOps Server (on-premises)
		baseURL = strings.TrimSuffix(config.BaseURL, "/")
		isCloud = false
	}

	return &AzureClient{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    baseURL,
		isCloud:    isCloud,
	}, nil
}

// TestConnection verifies the connection and returns user/org info
func (c *AzureClient) TestConnection(ctx context.Context) (*ConnectionTestResult, error) {
	result := &ConnectionTestResult{Success: false}

	// Get authenticated user
	user, err := c.GetUser(ctx)
	if err != nil {
		result.Message = fmt.Sprintf("Authentication failed: %v", err)
		return result, nil
	}
	result.User = user

	// If organization is specified, verify access to it
	if c.config.Organization != "" {
		org, err := c.getOrganization(ctx, c.config.Organization)
		if err != nil {
			result.Message = fmt.Sprintf("Cannot access organization '%s': %v", c.config.Organization, err)
			return result, nil
		}
		result.Organization = org
		result.RepoCount = org.RepoCount
	} else {
		// Count repositories
		repos, err := c.ListRepositories(ctx, ListOptions{PerPage: 1})
		if err == nil {
			result.RepoCount = repos.Total
		}
	}

	result.Success = true
	result.Message = connectionSuccessful
	return result, nil
}

// GetUser returns the authenticated user
func (c *AzureClient) GetUser(ctx context.Context) (*User, error) {
	// Azure DevOps uses the connection data API to get current user
	// For cloud: https://app.vssps.visualstudio.com/_apis/connectionData
	// For server: {baseURL}/_apis/connectionData

	var apiURL string
	if c.isCloud {
		apiURL = "https://app.vssps.visualstudio.com/_apis/connectionData"
	} else {
		apiURL = c.baseURL + "/_apis/connectionData"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrAuthFailed.Wrap(fmt.Errorf("invalid or expired token"))
	}

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Limit response body to 1MB to prevent memory exhaustion
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body))
	}

	var connData struct {
		AuthenticatedUser struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			UniqueName  string `json:"uniqueName"`
		} `json:"authenticatedUser"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&connData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &User{
		ID:       connData.AuthenticatedUser.ID,
		Username: connData.AuthenticatedUser.UniqueName,
		Name:     connData.AuthenticatedUser.DisplayName,
		Email:    connData.AuthenticatedUser.UniqueName,
	}, nil
}

// ListOrganizations returns organizations/projects the user has access to
func (c *AzureClient) ListOrganizations(ctx context.Context, opts ListOptions) ([]Organization, error) {
	if opts.PerPage == 0 {
		opts.PerPage = 100
	}

	// In Azure DevOps, we list projects within an organization
	// If no organization is set, we can't list organizations from the API directly
	// as there's no single endpoint to list all organizations a user has access to
	if c.config.Organization == "" {
		// Return empty list - user needs to specify organization
		return []Organization{}, nil
	}

	// List projects within the organization
	projects, err := c.listProjects(ctx, c.config.Organization, opts)
	if err != nil {
		return nil, err
	}

	return projects, nil
}

// listProjects lists all projects in an organization
func (c *AzureClient) listProjects(ctx context.Context, org string, opts ListOptions) ([]Organization, error) {
	skip := (opts.Page - 1) * opts.PerPage
	apiURL := fmt.Sprintf("%s/%s/_apis/projects?api-version=7.0&$top=%d&$skip=%d",
		c.baseURL, url.PathEscape(org), opts.PerPage, skip)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Limit response body to 1MB to prevent memory exhaustion
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Count int `json:"count"`
		Value []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			URL         string `json:"url"`
			State       string `json:"state"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	orgs := make([]Organization, len(result.Value))
	for i, p := range result.Value {
		orgs[i] = Organization{
			ID:          p.ID,
			Name:        p.Name,
			Description: p.Description,
		}
	}

	return orgs, nil
}

// ListRepositories returns repositories accessible to the user
func (c *AzureClient) ListRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	if opts.PerPage == 0 {
		opts.PerPage = 100
	}
	if opts.Page == 0 {
		opts.Page = 1
	}

	if c.config.Organization == "" {
		return nil, fmt.Errorf("organization is required for Azure DevOps")
	}

	// First, get all projects in the organization
	projects, err := c.listProjects(ctx, c.config.Organization, ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}

	// Collect repositories from all projects
	var allRepos []Repository
	for _, project := range projects {
		repos, err := c.listProjectRepositories(ctx, c.config.Organization, project.Name, opts)
		if err != nil {
			continue // Skip projects we can't access
		}
		allRepos = append(allRepos, repos...)
	}

	// Apply search filter if specified
	if opts.Search != "" {
		searchLower := strings.ToLower(opts.Search)
		var filtered []Repository
		for _, repo := range allRepos {
			if strings.Contains(strings.ToLower(repo.Name), searchLower) ||
				strings.Contains(strings.ToLower(repo.FullName), searchLower) {
				filtered = append(filtered, repo)
			}
		}
		allRepos = filtered
	}

	// Apply pagination
	total := len(allRepos)
	start := (opts.Page - 1) * opts.PerPage
	end := start + opts.PerPage
	if start >= total {
		return &ListResult{
			Repositories: []Repository{},
			Total:        total,
			HasMore:      false,
			NextPage:     0,
		}, nil
	}
	if end > total {
		end = total
	}

	hasMore := end < total
	nextPage := 0
	if hasMore {
		nextPage = opts.Page + 1
	}

	return &ListResult{
		Repositories: allRepos[start:end],
		Total:        total,
		HasMore:      hasMore,
		NextPage:     nextPage,
	}, nil
}

// listProjectRepositories lists repositories in a specific project
func (c *AzureClient) listProjectRepositories(ctx context.Context, org, project string, _ ListOptions) ([]Repository, error) {
	apiURL := fmt.Sprintf("%s/%s/%s/_apis/git/repositories?api-version=7.0",
		c.baseURL, url.PathEscape(org), url.PathEscape(project))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Count int         `json:"count"`
		Value []azureRepo `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return convertAzureRepos(result.Value, c.baseURL, org), nil
}

// GetRepository returns a single repository by full name (project/repo)
func (c *AzureClient) GetRepository(ctx context.Context, fullName string) (*Repository, error) {
	if c.config.Organization == "" {
		return nil, fmt.Errorf("organization is required for Azure DevOps")
	}

	// fullName format: project/repo or just repo (if project is in Organization field)
	parts := strings.SplitN(fullName, "/", 2)
	var project, repoName string
	if len(parts) == 2 {
		project = parts[0]
		repoName = parts[1]
	} else {
		repoName = fullName
		// Try to find the repo in all projects
		projects, err := c.listProjects(ctx, c.config.Organization, ListOptions{PerPage: 100})
		if err != nil {
			return nil, err
		}
		for _, p := range projects {
			repo, err := c.getRepositoryInProject(ctx, c.config.Organization, p.Name, repoName)
			if err == nil {
				return repo, nil
			}
		}
		return nil, ErrNotFound.Wrap(fmt.Errorf("repository %s not found", fullName))
	}

	return c.getRepositoryInProject(ctx, c.config.Organization, project, repoName)
}

func (c *AzureClient) getRepositoryInProject(ctx context.Context, org, project, repoName string) (*Repository, error) {
	apiURL := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s?api-version=7.0",
		c.baseURL, url.PathEscape(org), url.PathEscape(project), url.PathEscape(repoName))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("repository %s/%s not found", project, repoName))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var repoData azureRepo
	if err := json.NewDecoder(resp.Body).Decode(&repoData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	repos := convertAzureRepos([]azureRepo{repoData}, c.baseURL, org)
	if len(repos) == 0 {
		return nil, ErrNotFound
	}

	return &repos[0], nil
}

// getOrganization retrieves organization details
func (c *AzureClient) getOrganization(ctx context.Context, org string) (*Organization, error) {
	// Get projects count as a proxy for organization validity
	projects, err := c.listProjects(ctx, org, ListOptions{PerPage: 1})
	if err != nil {
		return nil, err
	}

	// Count all repositories across all projects
	allProjects, err := c.listProjects(ctx, org, ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}

	repoCount := 0
	for _, p := range allProjects {
		repos, err := c.listProjectRepositories(ctx, org, p.Name, ListOptions{PerPage: 100})
		if err == nil {
			repoCount += len(repos)
		}
	}

	// Determine display name
	displayName := org
	if len(projects) > 0 {
		displayName = org
	}

	return &Organization{
		ID:        org,
		Name:      displayName,
		RepoCount: repoCount,
	}, nil
}

// setAuthHeaders sets the authentication headers for Azure DevOps
func (c *AzureClient) setAuthHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Azure DevOps uses Basic auth with PAT as password (username can be empty)
	req.SetBasicAuth("", c.config.AccessToken)
	req.Header.Set("User-Agent", defaultUserAgent)
}

// Azure DevOps repository structure
type azureRepo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	WebURL        string `json:"webUrl"`
	SSHURL        string `json:"sshUrl"`
	RemoteURL     string `json:"remoteUrl"`
	DefaultBranch string `json:"defaultBranch"`
	Size          int64  `json:"size"`
	IsDisabled    bool   `json:"isDisabled"`
	IsFork        bool   `json:"isFork"`
	Project       struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		State string `json:"state"`
	} `json:"project"`
}

func convertAzureRepos(azRepos []azureRepo, baseURL, org string) []Repository {
	repos := make([]Repository, len(azRepos))
	for i, r := range azRepos {
		fullName := fmt.Sprintf("%s/%s", r.Project.Name, r.Name)

		// Construct web URL if not provided
		webURL := r.WebURL
		if webURL == "" {
			webURL = fmt.Sprintf("%s/%s/%s/_git/%s", baseURL, org, r.Project.Name, r.Name)
		}

		// Construct clone URL if not provided
		cloneURL := r.RemoteURL
		if cloneURL == "" {
			cloneURL = fmt.Sprintf("%s/%s/%s/_git/%s", baseURL, org, r.Project.Name, r.Name)
		}

		// Extract default branch name (remove refs/heads/ prefix)
		defaultBranch := strings.TrimPrefix(r.DefaultBranch, azureDefaultBranchPrefix)

		repos[i] = Repository{
			ID:            r.ID,
			Name:          r.Name,
			FullName:      fullName,
			HTMLURL:       webURL,
			CloneURL:      cloneURL,
			SSHURL:        r.SSHURL,
			DefaultBranch: defaultBranch,
			IsPrivate:     true, // Azure DevOps repos are private by default
			IsFork:        r.IsFork,
			IsArchived:    r.IsDisabled,
			Size:          int(r.Size / 1024), // Convert to KB
		}
	}
	return repos
}
