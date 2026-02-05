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

// GitHubClient implements the Client interface for GitHub
type GitHubClient struct {
	config     Config
	httpClient *http.Client
	baseURL    string
}

// NewGitHubClient creates a new GitHub client
func NewGitHubClient(config Config) (*GitHubClient, error) {
	baseURL := "https://api.github.com"
	if config.BaseURL != "" && config.BaseURL != "https://github.com" {
		// For GitHub Enterprise, construct the API URL
		baseURL = strings.TrimSuffix(config.BaseURL, "/") + "/api/v3"
	}

	return &GitHubClient{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    baseURL,
	}, nil
}

// TestConnection verifies the connection and returns user/org info
func (c *GitHubClient) TestConnection(ctx context.Context) (*ConnectionTestResult, error) {
	result := &ConnectionTestResult{Success: false}

	// Get authenticated user
	user, err := c.GetUser(ctx)
	if err != nil {
		result.Message = fmt.Sprintf("Authentication failed: %v", err)
		return result, nil
	}
	result.User = user

	// Get rate limit info
	rateLimit, err := c.getRateLimit(ctx)
	if err == nil {
		result.RateLimit = rateLimit
	}

	// If organization is specified, verify access to it
	if c.config.Organization != "" {
		// First try as organization
		org, err := c.getOrganization(ctx, c.config.Organization)
		if err != nil {
			// If not found as org, try as a user
			userInfo, userErr := c.getUserByUsername(ctx, c.config.Organization)
			if userErr != nil {
				result.Message = fmt.Sprintf("Cannot access organization or user '%s': %v", c.config.Organization, err)
				return result, err
			}
			result.Organization = userInfo
			result.RepoCount = userInfo.RepoCount
		} else {
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
func (c *GitHubClient) GetUser(ctx context.Context) (*User, error) {
	resp, err := c.doRequest(ctx, "GET", "/user", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuthFailed.Wrap(fmt.Errorf("invalid or expired token"))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var ghUser struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &User{
		ID:        strconv.Itoa(ghUser.ID),
		Username:  ghUser.Login,
		Name:      ghUser.Name,
		Email:     ghUser.Email,
		AvatarURL: ghUser.AvatarURL,
	}, nil
}

// ListOrganizations returns organizations the user has access to
func (c *GitHubClient) ListOrganizations(ctx context.Context, opts ListOptions) ([]Organization, error) {
	if opts.PerPage == 0 {
		opts.PerPage = 30
	}
	if opts.Page == 0 {
		opts.Page = 1
	}

	path := fmt.Sprintf("/user/orgs?page=%d&per_page=%d", opts.Page, opts.PerPage)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var ghOrgs []struct {
		ID          int    `json:"id"`
		Login       string `json:"login"`
		Description string `json:"description"`
		AvatarURL   string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghOrgs); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	orgs := make([]Organization, len(ghOrgs))
	for i, o := range ghOrgs {
		orgs[i] = Organization{
			ID:          strconv.Itoa(o.ID),
			Name:        o.Login,
			Description: o.Description,
			AvatarURL:   o.AvatarURL,
		}
	}

	return orgs, nil
}

// ListRepositories returns repositories accessible to the user
func (c *GitHubClient) ListRepositories(ctx context.Context, opts ListOptions) (*ListResult, error) {
	if opts.PerPage == 0 {
		opts.PerPage = 30
	}
	if opts.Page == 0 {
		opts.Page = 1
	}

	var path string
	if c.config.Organization != "" {
		// First try as organization, if fails try as user
		orgPath := fmt.Sprintf("/orgs/%s/repos?page=%d&per_page=%d&sort=updated&direction=desc",
			url.PathEscape(c.config.Organization), opts.Page, opts.PerPage)

		resp, err := c.doRequest(ctx, "GET", orgPath, nil)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			path = orgPath
		} else {
			if resp != nil {
				resp.Body.Close()
			}
			// Try as user
			path = fmt.Sprintf("/users/%s/repos?page=%d&per_page=%d&sort=updated&direction=desc",
				url.PathEscape(c.config.Organization), opts.Page, opts.PerPage)
		}
	} else {
		// List user's repositories (including org repos they have access to)
		path = fmt.Sprintf("/user/repos?page=%d&per_page=%d&sort=updated&direction=desc&affiliation=owner,collaborator,organization_member",
			opts.Page, opts.PerPage)
	}

	// Add search filter if specified
	if opts.Search != "" {
		// Use GitHub search API for filtering
		var query string
		if c.config.Organization != "" {
			// Search in org or user
			query = fmt.Sprintf("user:%s %s", c.config.Organization, opts.Search)
		} else {
			query = opts.Search
		}
		path = fmt.Sprintf("/search/repositories?q=%s&page=%d&per_page=%d&sort=updated&order=desc",
			url.QueryEscape(query), opts.Page, opts.PerPage)
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

	// Parse response based on endpoint
	var repos []Repository
	var total int

	if opts.Search != "" {
		// Search API returns a different format
		var searchResult struct {
			TotalCount int `json:"total_count"`
			Items      []ghRepo
		}
		if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		total = searchResult.TotalCount
		repos = convertGHRepos(searchResult.Items)
	} else {
		// Regular list API
		var ghRepos []ghRepo
		if err := json.NewDecoder(resp.Body).Decode(&ghRepos); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		repos = convertGHRepos(ghRepos)

		// Get total from Link header if available
		total = len(repos)
		if linkHeader := resp.Header.Get("Link"); linkHeader != "" {
			if strings.Contains(linkHeader, "last") {
				// There are more pages
				total = len(repos) * 10 // Estimate
			}
		}
	}

	hasMore := len(repos) == opts.PerPage
	nextPage := 0
	if hasMore {
		nextPage = opts.Page + 1
	}

	return &ListResult{
		Repositories: repos,
		Total:        total,
		HasMore:      hasMore,
		NextPage:     nextPage,
	}, nil
}

// GetRepository returns a single repository by full name
func (c *GitHubClient) GetRepository(ctx context.Context, fullName string) (*Repository, error) {
	path := fmt.Sprintf("/repos/%s", fullName)
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

	var repoData ghRepo
	if err := json.NewDecoder(resp.Body).Decode(&repoData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	repos := convertGHRepos([]ghRepo{repoData})
	if len(repos) == 0 {
		return nil, ErrNotFound
	}

	repo := repos[0]

	// Fetch languages for this repository
	languages, err := c.getRepositoryLanguages(ctx, fullName)
	if err == nil && languages != nil {
		repo.Languages = languages
	}

	return &repo, nil
}

// getRepositoryLanguages fetches all languages for a repository
func (c *GitHubClient) getRepositoryLanguages(ctx context.Context, fullName string) (map[string]int, error) {
	path := fmt.Sprintf("/repos/%s/languages", fullName)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// GitHub returns languages as {"Go": 12345, "JavaScript": 6789}
	// where the value is bytes of code
	var languages map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&languages); err != nil {
		return nil, fmt.Errorf("failed to decode languages: %w", err)
	}

	return languages, nil
}

// Helper methods

func (c *GitHubClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "Bearer "+c.config.AccessToken)
	req.Header.Set("User-Agent", defaultUserAgent)

	return c.httpClient.Do(req)
}

func (c *GitHubClient) getOrganization(ctx context.Context, name string) (*Organization, error) {
	path := fmt.Sprintf("/orgs/%s", url.PathEscape(name))
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("organization %s not found", name))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var ghOrg struct {
		ID                int    `json:"id"`
		Login             string `json:"login"`
		Name              string `json:"name"`
		Description       string `json:"description"`
		AvatarURL         string `json:"avatar_url"`
		PublicRepos       int    `json:"public_repos"`
		TotalPrivateRepos int    `json:"total_private_repos"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghOrg); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &Organization{
		ID:          strconv.Itoa(ghOrg.ID),
		Name:        ghOrg.Login,
		Description: ghOrg.Description,
		AvatarURL:   ghOrg.AvatarURL,
		RepoCount:   ghOrg.PublicRepos + ghOrg.TotalPrivateRepos,
	}, nil
}

// getUserByUsername retrieves a user by username (for user namespace)
func (c *GitHubClient) getUserByUsername(ctx context.Context, username string) (*Organization, error) {
	path := fmt.Sprintf("/users/%s", url.PathEscape(username))
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound.Wrap(fmt.Errorf("user %s not found", username))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var ghUser struct {
		ID          int    `json:"id"`
		Login       string `json:"login"`
		Name        string `json:"name"`
		Bio         string `json:"bio"`
		AvatarURL   string `json:"avatar_url"`
		PublicRepos int    `json:"public_repos"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &Organization{
		ID:          strconv.Itoa(ghUser.ID),
		Name:        ghUser.Login,
		Description: ghUser.Bio,
		AvatarURL:   ghUser.AvatarURL,
		RepoCount:   ghUser.PublicRepos,
	}, nil
}

func (c *GitHubClient) getRateLimit(ctx context.Context) (*RateLimit, error) {
	resp, err := c.doRequest(ctx, "GET", "/rate_limit", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var rateLimit struct {
		Resources struct {
			Core struct {
				Limit     int   `json:"limit"`
				Remaining int   `json:"remaining"`
				Reset     int64 `json:"reset"`
			} `json:"core"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rateLimit); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &RateLimit{
		Limit:     rateLimit.Resources.Core.Limit,
		Remaining: rateLimit.Resources.Core.Remaining,
		ResetAt:   time.Unix(rateLimit.Resources.Core.Reset, 0),
	}, nil
}

// ghRepo is the GitHub API repository response structure
type ghRepo struct {
	ID              int       `json:"id"`
	Name            string    `json:"name"`
	FullName        string    `json:"full_name"`
	Description     string    `json:"description"`
	HTMLURL         string    `json:"html_url"`
	CloneURL        string    `json:"clone_url"`
	SSHURL          string    `json:"ssh_url"`
	DefaultBranch   string    `json:"default_branch"`
	Private         bool      `json:"private"`
	Fork            bool      `json:"fork"`
	Archived        bool      `json:"archived"`
	Language        string    `json:"language"`
	Topics          []string  `json:"topics"`
	StargazersCount int       `json:"stargazers_count"`
	ForksCount      int       `json:"forks_count"`
	Size            int       `json:"size"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	PushedAt        time.Time `json:"pushed_at"`
}

func convertGHRepos(ghRepos []ghRepo) []Repository {
	repos := make([]Repository, len(ghRepos))
	for i, r := range ghRepos {
		repos[i] = Repository{
			ID:            strconv.Itoa(r.ID),
			Name:          r.Name,
			FullName:      r.FullName,
			Description:   r.Description,
			HTMLURL:       r.HTMLURL,
			CloneURL:      r.CloneURL,
			SSHURL:        r.SSHURL,
			DefaultBranch: r.DefaultBranch,
			IsPrivate:     r.Private,
			IsFork:        r.Fork,
			IsArchived:    r.Archived,
			Language:      r.Language,
			Topics:        r.Topics,
			Stars:         r.StargazersCount,
			Forks:         r.ForksCount,
			Size:          r.Size,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
			PushedAt:      r.PushedAt,
		}
	}
	return repos
}
