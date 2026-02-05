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

// BitbucketClient implements the Client interface for Bitbucket
// Supports both Bitbucket Cloud (bitbucket.org) and Bitbucket Server/Data Center
type BitbucketClient struct {
	config     Config
	httpClient *http.Client
	baseURL    string
	isCloud    bool
}

// NewBitbucketClient creates a new Bitbucket client
func NewBitbucketClient(config Config) (*BitbucketClient, error) {
	baseURL := "https://api.bitbucket.org/2.0"
	isCloud := true

	if config.BaseURL != "" && config.BaseURL != "https://bitbucket.org" {
		// For Bitbucket Server/Data Center
		baseURL = strings.TrimSuffix(config.BaseURL, "/") + "/rest/api/1.0"
		isCloud = false
	}

	return &BitbucketClient{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    baseURL,
		isCloud:    isCloud,
	}, nil
}

// TestConnection verifies the connection and returns user/org info
func (c *BitbucketClient) TestConnection(ctx context.Context) (*ConnectionTestResult, error) {
	result := &ConnectionTestResult{Success: false}

	// Get authenticated user
	user, err := c.GetUser(ctx)
	if err != nil {
		result.Message = fmt.Sprintf("Authentication failed: %v", err)
		return result, nil
	}
	result.User = user

	// If workspace/project is specified, verify access to it
	if c.config.Organization != "" {
		// Check if organization matches current user - show all repos
		if user.Username == c.config.Organization {
			repos, err := c.ListRepositories(ctx, ListOptions{PerPage: 1})
			if err == nil {
				result.RepoCount = repos.Total
			}
			result.Organization = &Organization{
				ID:        user.ID,
				Name:      user.Username,
				RepoCount: result.RepoCount,
			}
		} else {
			org, err := c.getWorkspaceOrProject(ctx, c.config.Organization)
			if err != nil {
				result.Message = fmt.Sprintf("Cannot access workspace/project '%s': %v", c.config.Organization, err)
				return result, nil
			}
			result.Organization = org
			result.RepoCount = org.RepoCount
		}
	} else {
		// Count user repositories
		repos, err := c.ListRepositories(ctx, ListOptions{PerPage: 1})
		if err == nil {
			result.RepoCount = repos.Total
		}
	}

	result.Success = true
	result.Message = "Connection successful"
	return result, nil
}

// GetUser returns the authenticated user
func (c *BitbucketClient) GetUser(ctx context.Context) (*User, error) {
	var path string
	if c.isCloud {
		path = "/user"
	} else {
		// Bitbucket Server uses different endpoint
		path = "/users"
		// Get current user from application properties
		resp, err := c.doRequest(ctx, "GET", "/application-properties", nil)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		// For Server, use the /users endpoint with a workaround
		path = "/users?limit=1&filter=me"
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
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

	if c.isCloud {
		var bbUser struct {
			UUID        string `json:"uuid"`
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			Links       struct {
				Avatar struct {
					Href string `json:"href"`
				} `json:"avatar"`
			} `json:"links"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&bbUser); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		return &User{
			ID:        bbUser.UUID,
			Username:  bbUser.Username,
			Name:      bbUser.DisplayName,
			AvatarURL: bbUser.Links.Avatar.Href,
		}, nil
	}

	// Bitbucket Server response
	var bbServerUser struct {
		Name         string `json:"name"`
		EmailAddress string `json:"emailAddress"`
		ID           int    `json:"id"`
		DisplayName  string `json:"displayName"`
		Slug         string `json:"slug"`
		Links        struct {
			Self []struct {
				Href string `json:"href"`
			} `json:"self"`
		} `json:"links"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&bbServerUser); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &User{
		ID:       fmt.Sprintf("%d", bbServerUser.ID),
		Username: bbServerUser.Slug,
		Name:     bbServerUser.DisplayName,
		Email:    bbServerUser.EmailAddress,
	}, nil
}

// ListOrganizations returns workspaces/projects the user has access to
func (c *BitbucketClient) ListOrganizations(ctx context.Context, opts ListOptions) ([]Organization, error) {
	if opts.PerPage == 0 {
		opts.PerPage = 20
	}
	if opts.Page == 0 {
		opts.Page = 1
	}

	if c.isCloud {
		return c.listCloudWorkspaces(ctx, opts)
	}
	return c.listServerProjects(ctx, opts)
}

func (c *BitbucketClient) listCloudWorkspaces(ctx context.Context, opts ListOptions) ([]Organization, error) {
	path := fmt.Sprintf("/user/permissions/workspaces?page=%d&pagelen=%d", opts.Page, opts.PerPage)

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Values []struct {
			Workspace struct {
				UUID string `json:"uuid"`
				Slug string `json:"slug"`
				Name string `json:"name"`
			} `json:"workspace"`
		} `json:"values"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	orgs := make([]Organization, len(result.Values))
	for i, v := range result.Values {
		orgs[i] = Organization{
			ID:   v.Workspace.UUID,
			Name: v.Workspace.Slug,
		}
	}

	return orgs, nil
}

func (c *BitbucketClient) listServerProjects(ctx context.Context, opts ListOptions) ([]Organization, error) {
	start := (opts.Page - 1) * opts.PerPage
	path := fmt.Sprintf("/projects?start=%d&limit=%d", start, opts.PerPage)

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Values []struct {
			ID          int    `json:"id"`
			Key         string `json:"key"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"values"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	orgs := make([]Organization, len(result.Values))
	for i, p := range result.Values {
		orgs[i] = Organization{
			ID:          fmt.Sprintf("%d", p.ID),
			Name:        p.Key,
			Description: p.Description,
		}
	}

	return orgs, nil
}

// ListRepositories returns repositories accessible to the user
func (c *BitbucketClient) ListRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	if opts.PerPage == 0 {
		opts.PerPage = 20
	}
	if opts.Page == 0 {
		opts.Page = 1
	}

	if c.isCloud {
		return c.listCloudRepositories(ctx, opts)
	}
	return c.listServerRepositories(ctx, opts)
}

func (c *BitbucketClient) listCloudRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	var path string
	if c.config.Organization != "" {
		path = fmt.Sprintf("/repositories/%s?page=%d&pagelen=%d&sort=-updated_on",
			url.PathEscape(c.config.Organization), opts.Page, opts.PerPage)
	} else {
		// List user's repositories
		path = fmt.Sprintf("/user/permissions/repositories?page=%d&pagelen=%d&sort=-repository.updated_on",
			opts.Page, opts.PerPage)
	}

	// Add search filter if specified
	if opts.Search != "" {
		if c.config.Organization != "" {
			path += "&q=name~\"" + url.QueryEscape(opts.Search) + "\""
		}
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Limit response body to 1MB to prevent memory exhaustion
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body))
	}

	if c.config.Organization != "" {
		// Direct repository list
		var result struct {
			Values []bbCloudRepo `json:"values"`
			Size   int           `json:"size"`
			Next   string        `json:"next"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		repos := convertBBCloudRepos(result.Values)
		return &ListResult{
			Repositories: repos,
			Total:        result.Size,
			HasMore:      result.Next != "",
			NextPage:     opts.Page + 1,
		}, nil
	}

	// User permissions endpoint
	var result struct {
		Values []struct {
			Repository bbCloudRepo `json:"repository"`
		} `json:"values"`
		Size int    `json:"size"`
		Next string `json:"next"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	repoList := make([]bbCloudRepo, len(result.Values))
	for i, v := range result.Values {
		repoList[i] = v.Repository
	}
	repos := convertBBCloudRepos(repoList)

	return &ListResult{
		Repositories: repos,
		Total:        result.Size,
		HasMore:      result.Next != "",
		NextPage:     opts.Page + 1,
	}, nil
}

func (c *BitbucketClient) listServerRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	start := (opts.Page - 1) * opts.PerPage

	var path string
	if c.config.Organization != "" {
		path = fmt.Sprintf("/projects/%s/repos?start=%d&limit=%d",
			url.PathEscape(c.config.Organization), start, opts.PerPage)
	} else {
		path = fmt.Sprintf("/repos?start=%d&limit=%d", start, opts.PerPage)
	}

	// Add search filter if specified
	if opts.Search != "" {
		path += "&filter=" + url.QueryEscape(opts.Search)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
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
		Values        []bbServerRepo `json:"values"`
		Size          int            `json:"size"`
		IsLastPage    bool           `json:"isLastPage"`
		NextPageStart int            `json:"nextPageStart"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	repos := convertBBServerRepos(result.Values, c.config.BaseURL)

	nextPage := 0
	if !result.IsLastPage {
		nextPage = opts.Page + 1
	}

	return &ListResult{
		Repositories: repos,
		Total:        result.Size,
		HasMore:      !result.IsLastPage,
		NextPage:     nextPage,
	}, nil
}

// GetRepository returns a single repository by full name
func (c *BitbucketClient) GetRepository(ctx context.Context, fullName string) (*Repository, error) {
	if c.isCloud {
		return c.getCloudRepository(ctx, fullName)
	}
	return c.getServerRepository(ctx, fullName)
}

func (c *BitbucketClient) getCloudRepository(ctx context.Context, fullName string) (*Repository, error) {
	path := fmt.Sprintf("/repositories/%s", fullName)

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("repository %s not found", fullName))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var repoData bbCloudRepo
	if err := json.NewDecoder(resp.Body).Decode(&repoData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	repos := convertBBCloudRepos([]bbCloudRepo{repoData})
	if len(repos) == 0 {
		return nil, ErrNotFound
	}

	return &repos[0], nil
}

func (c *BitbucketClient) getServerRepository(ctx context.Context, fullName string) (*Repository, error) {
	// fullName format: PROJECT_KEY/repo-slug
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository name format, expected: PROJECT_KEY/repo-slug")
	}

	path := fmt.Sprintf("/projects/%s/repos/%s", url.PathEscape(parts[0]), url.PathEscape(parts[1]))

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("repository %s not found", fullName))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var repoData bbServerRepo
	if err := json.NewDecoder(resp.Body).Decode(&repoData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	repos := convertBBServerRepos([]bbServerRepo{repoData}, c.config.BaseURL)
	if len(repos) == 0 {
		return nil, ErrNotFound
	}

	return &repos[0], nil
}

// getWorkspaceOrProject retrieves workspace (Cloud) or project (Server) details
func (c *BitbucketClient) getWorkspaceOrProject(ctx context.Context, name string) (*Organization, error) {
	if c.isCloud {
		return c.getCloudWorkspace(ctx, name)
	}
	return c.getServerProject(ctx, name)
}

func (c *BitbucketClient) getCloudWorkspace(ctx context.Context, slug string) (*Organization, error) {
	path := fmt.Sprintf("/workspaces/%s", url.PathEscape(slug))

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("workspace %s not found", slug))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var workspace struct {
		UUID string `json:"uuid"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&workspace); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Get repository count
	repoCount := 0
	repoPath := fmt.Sprintf("/repositories/%s?pagelen=1", url.PathEscape(slug))
	repoResp, err := c.doRequest(ctx, "GET", repoPath, nil)
	if err == nil {
		defer repoResp.Body.Close()
		var repoResult struct {
			Size int `json:"size"`
		}
		if json.NewDecoder(repoResp.Body).Decode(&repoResult) == nil {
			repoCount = repoResult.Size
		}
	}

	return &Organization{
		ID:        workspace.UUID,
		Name:      workspace.Slug,
		RepoCount: repoCount,
	}, nil
}

func (c *BitbucketClient) getServerProject(ctx context.Context, key string) (*Organization, error) {
	path := fmt.Sprintf("/projects/%s", url.PathEscape(key))

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("project %s not found", key))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var project struct {
		ID          int    `json:"id"`
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Get repository count
	repoCount := 0
	repoPath := fmt.Sprintf("/projects/%s/repos?limit=1", url.PathEscape(key))
	repoResp, err := c.doRequest(ctx, "GET", repoPath, nil)
	if err == nil {
		defer repoResp.Body.Close()
		var repoResult struct {
			Size int `json:"size"`
		}
		if json.NewDecoder(repoResp.Body).Decode(&repoResult) == nil {
			repoCount = repoResult.Size
		}
	}

	return &Organization{
		ID:          fmt.Sprintf("%d", project.ID),
		Name:        project.Key,
		Description: project.Description,
		RepoCount:   repoCount,
	}, nil
}

// doRequest performs an HTTP request with authentication
func (c *BitbucketClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.AccessToken)
	req.Header.Set("User-Agent", defaultUserAgent)

	return c.httpClient.Do(req)
}

// Bitbucket Cloud repository structure
type bbCloudRepo struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	IsPrivate   bool   `json:"is_private"`
	Language    string `json:"language"`
	ForkPolicy  string `json:"fork_policy"`
	Size        int    `json:"size"`
	CreatedOn   string `json:"created_on"`
	UpdatedOn   string `json:"updated_on"`
	Links       struct {
		HTML  struct{ Href string } `json:"html"`
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
	} `json:"links"`
	MainBranch struct {
		Name string `json:"name"`
	} `json:"mainbranch"`
	Parent *struct{} `json:"parent"`
}

// Bitbucket Server repository structure
type bbServerRepo struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	State       string `json:"state"`
	Forkable    bool   `json:"forkable"`
	Public      bool   `json:"public"`
	Project     struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"project"`
	Links struct {
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
		Self []struct {
			Href string `json:"href"`
		} `json:"self"`
	} `json:"links"`
}

func convertBBCloudRepos(bbRepos []bbCloudRepo) []Repository {
	repos := make([]Repository, len(bbRepos))
	for i, r := range bbRepos {
		var cloneURL, sshURL string
		for _, clone := range r.Links.Clone {
			if clone.Name == "https" {
				cloneURL = clone.Href
			} else if clone.Name == "ssh" {
				sshURL = clone.Href
			}
		}

		var createdAt, updatedAt time.Time
		if r.CreatedOn != "" {
			createdAt, _ = time.Parse(time.RFC3339, r.CreatedOn)
		}
		if r.UpdatedOn != "" {
			updatedAt, _ = time.Parse(time.RFC3339, r.UpdatedOn)
		}

		repos[i] = Repository{
			ID:            r.UUID,
			Name:          r.Name,
			FullName:      r.FullName,
			Description:   r.Description,
			HTMLURL:       r.Links.HTML.Href,
			CloneURL:      cloneURL,
			SSHURL:        sshURL,
			DefaultBranch: r.MainBranch.Name,
			IsPrivate:     r.IsPrivate,
			IsFork:        r.Parent != nil,
			Language:      r.Language,
			Size:          r.Size,
			CreatedAt:     createdAt,
			UpdatedAt:     updatedAt,
		}
	}
	return repos
}

func convertBBServerRepos(bbRepos []bbServerRepo, _ string) []Repository {
	repos := make([]Repository, len(bbRepos))
	for i, r := range bbRepos {
		var cloneURL, sshURL, htmlURL string
		for _, clone := range r.Links.Clone {
			if clone.Name == "http" || clone.Name == "https" {
				cloneURL = clone.Href
			} else if clone.Name == "ssh" {
				sshURL = clone.Href
			}
		}
		if len(r.Links.Self) > 0 {
			htmlURL = r.Links.Self[0].Href
		}

		fullName := fmt.Sprintf("%s/%s", r.Project.Key, r.Slug)

		repos[i] = Repository{
			ID:          fmt.Sprintf("%d", r.ID),
			Name:        r.Name,
			FullName:    fullName,
			Description: r.Description,
			HTMLURL:     htmlURL,
			CloneURL:    cloneURL,
			SSHURL:      sshURL,
			IsPrivate:   !r.Public,
			IsArchived:  r.State == "OFFLINE",
		}
	}
	return repos
}
