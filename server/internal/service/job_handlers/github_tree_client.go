package job_handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"ManScan/server/internal/service"
)

const (
	defaultGitHubAPIBaseURL = "https://api.github.com"
	defaultCVEOwner         = "CVEProject"
	defaultCVERepository    = "cvelistV5"
	githubTreeMaxAttempts   = 3
)

var cveFileNamePattern = regexp.MustCompile(`^CVE-\d{4}-\d+\.json$`)

type treeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type treeResponse struct {
	Tree      []treeEntry `json:"tree"`
	Truncated bool        `json:"truncated"`
}

type githubTreeRetryError struct{ err error }

func (e *githubTreeRetryError) Error() string {
	return fmt.Sprintf("GitHub tree request failed after %d attempts: %v", githubTreeMaxAttempts, e.err)
}

func (e *githubTreeRetryError) Unwrap() error { return e.err }

// GitHubTreeClient reads GitHub Git Tree metadata for one repository.
type GitHubTreeClient struct {
	HTTPClient *http.Client
	BaseURL    string
	Owner      string
	Repository string
	Token      string

	beforeRequest func(context.Context) error
	progress      *githubTreeProgress
}

// NewGitHubTreeClient creates a client for the CVEProject/cvelistV5 repository.
func NewGitHubTreeClient(token string) *GitHubTreeClient {
	return &GitHubTreeClient{
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		BaseURL:    defaultGitHubAPIBaseURL,
		Owner:      defaultCVEOwner,
		Repository: defaultCVERepository,
		Token:      token,
	}
}

// ListCVEFileNamesWithProgress reports whole-tree retrieval, retries and long network waits.
func (c *GitHubTreeClient) ListCVEFileNamesWithProgress(ctx context.Context, ref string, reporter service.ProgressReporter) ([]string, error) {
	client := *c
	client.progress = &githubTreeProgress{reporter: reporter, directory: "仓库根目录"}
	return client.ListCVEFileNames(ctx, ref)
}

// ListCVEFileNames returns sorted CVE names without the .json suffix.
func (c *GitHubTreeClient) ListCVEFileNames(ctx context.Context, ref string) ([]string, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, errors.New("git ref must not be empty")
	}

	root, err := c.getTree(ctx, ref, false)
	if err != nil {
		return nil, fmt.Errorf("read repository tree: %w", err)
	}
	if root.Truncated {
		return nil, errors.New("repository root tree response is truncated")
	}

	var sha string
	for _, entry := range root.Tree {
		if entry.Type == "tree" && entry.Path == "cves" && entry.SHA != "" {
			sha = entry.SHA
			break
		}
	}
	if sha == "" {
		return nil, errors.New("repository tree does not contain a cves directory")
	}
	if c.progress != nil {
		c.progress.completed = 1
		c.progress.directory = "cves"
	}
	if err := c.progress.report(ctx, "github_listing", "已定位 CVE 目录，开始整树读取"); err != nil {
		return nil, err
	}
	// Request the entire subtree once; never split it into directory requests.
	tree, err := c.getTree(ctx, sha, true)
	if err != nil {
		return nil, fmt.Errorf("read cves tree %q: %w", sha, err)
	}
	if tree.Truncated {
		return nil, errors.New("GitHub CVE 整树响应被截断，无法获取完整列表；已禁用子目录拆分读取，保留上一次成功文件")
	}
	seenNames := make(map[string]struct{})
	for _, entry := range tree.Tree {
		if entry.Type != "blob" {
			continue
		}
		name := entry.Path
		if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
			name = name[slash+1:]
		}
		if cveFileNamePattern.MatchString(name) {
			seenNames[strings.TrimSuffix(name, ".json")] = struct{}{}
		}
	}
	if c.progress != nil {
		c.progress.completed = 2
		c.progress.found = len(seenNames)
	}

	names := make([]string, 0, len(seenNames))
	for name := range seenNames {
		names = append(names, name)
	}
	sort.Strings(names)
	if err := c.progress.report(ctx, "github_finished", fmt.Sprintf("GitHub 列表获取完成，共 %d 个 CVE，准备写入文件", len(names))); err != nil {
		return nil, err
	}
	return names, nil
}

func (c *GitHubTreeClient) getTree(ctx context.Context, ref string, recursive bool) (treeResponse, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return treeResponse{}, err
		}
		// Every actual attempt shares the key's quota. Configuration/limiter
		// failures must stop immediately rather than become network retries.
		if c.beforeRequest != nil {
			if err := c.progress.run(ctx, "github_waiting", "正在等待 GitHub API Key 请求额度", c.beforeRequest); err != nil {
				return treeResponse{}, err
			}
		}
		if err := ctx.Err(); err != nil {
			return treeResponse{}, err
		}
		mode := "根目录"
		if recursive {
			mode = "整树"
		}
		var tree treeResponse
		err := c.progress.run(ctx, "github_requesting", fmt.Sprintf("正在%s读取 GitHub 目录，第 %d/%d 次尝试", mode, attempt+1, githubTreeMaxAttempts), func(requestCtx context.Context) error {
			var requestErr error
			tree, requestErr = c.getTreeOnce(requestCtx, ref, recursive)
			return requestErr
		})
		if ctx.Err() != nil {
			return treeResponse{}, ctx.Err()
		}
		if err == nil || !retryableGitHubTreeError(err) {
			return tree, err
		}
		if attempt+1 >= githubTreeMaxAttempts {
			return treeResponse{}, &githubTreeRetryError{err: err}
		}
		if reportErr := c.progress.report(ctx, "github_retrying", fmt.Sprintf("%s，%d 秒后进行第 %d/%d 次尝试", githubTreeRetryReason(err), 1<<attempt, attempt+2, githubTreeMaxAttempts)); reportErr != nil {
			return treeResponse{}, reportErr
		}
		timer := time.NewTimer(time.Second << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			return treeResponse{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func retryableGitHubTreeError(err error) bool {
	var progressError *githubTreeProgressError
	if errors.As(err, &progressError) {
		return false
	}
	var networkError net.Error
	return (errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (c *GitHubTreeClient) getTreeOnce(ctx context.Context, ref string, recursive bool) (treeResponse, error) {
	baseURL := strings.TrimRight(c.BaseURL, "/")
	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s", baseURL, c.Owner, c.Repository, url.PathEscape(ref))
	if recursive {
		endpoint += "?recursive=1"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return treeResponse{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "manscan-cve-file-names")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if c.progress != nil {
		c.progress.requests.Add(1)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return treeResponse{}, err
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests {
			return treeResponse{}, fmt.Errorf("GitHub API returned HTTP %d: access denied or rate limited; check GITHUB_TOKEN and GitHub rate limits", response.StatusCode)
		}
		return treeResponse{}, fmt.Errorf("GitHub API returned HTTP %d", response.StatusCode)
	}

	var tree treeResponse
	var reader io.Reader = response.Body
	if c.progress != nil {
		reader = githubTreeProgressReader{reader: reader, progress: c.progress}
	}
	if err := json.NewDecoder(io.LimitReader(reader, 32<<20)).Decode(&tree); err != nil {
		return treeResponse{}, fmt.Errorf("decode GitHub tree response: %w", err)
	}
	if tree.Tree == nil {
		return treeResponse{}, errors.New("GitHub tree response is missing the tree array")
	}
	return tree, nil
}
