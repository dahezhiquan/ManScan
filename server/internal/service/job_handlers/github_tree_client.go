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

// ListCVEFileNamesWithProgress reports traversal, retries and long network waits.
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

	type directory struct{ sha, path string }
	var stack []directory
	queued := make(map[string]struct{})
	for _, entry := range root.Tree {
		if entry.Type == "tree" && entry.Path == "cves" && entry.SHA != "" {
			stack = append(stack, directory{entry.SHA, "cves"})
			queued[entry.SHA] = struct{}{}
		}
	}
	if len(stack) == 0 {
		return nil, errors.New("repository tree does not contain a cves directory")
	}

	seenTrees := make(map[string]struct{})
	seenNames := make(map[string]struct{})
	if c.progress != nil {
		c.progress.completed = 1
		c.progress.pending = len(stack)
	}
	if err := c.progress.report(ctx, "github_traversing", "已定位 CVE 目录，开始遍历"); err != nil {
		return nil, err
	}
	for len(stack) > 0 {
		last := len(stack) - 1
		dir := stack[last]
		sha := dir.sha
		stack = stack[:last]
		if _, seen := seenTrees[sha]; seen {
			continue
		}
		seenTrees[sha] = struct{}{}
		if c.progress != nil {
			c.progress.directory = dir.path
			c.progress.pending = len(stack)
		}

		// Large recursive responses can time out before GitHub's truncation flag
		// arrives. Discard incomplete results and walk smaller subtrees instead.
		recursive := true
		tree, err := c.getTree(ctx, sha, recursive)
		var exhausted *githubTreeRetryError
		if err != nil && (ctx.Err() != nil || !errors.As(err, &exhausted)) {
			return nil, fmt.Errorf("read tree %q: %w", sha, err)
		}
		if err != nil || tree.Truncated {
			reason := "递归结果被截断"
			if err != nil {
				reason = githubTreeRetryReason(err) + "，重试已耗尽"
			}
			if reportErr := c.progress.report(ctx, "github_fallback", reason+"，改为逐层读取目录"); reportErr != nil {
				return nil, reportErr
			}
			recursive = false
			tree, err = c.getTree(ctx, sha, recursive)
			if err != nil {
				return nil, fmt.Errorf("read direct tree %q: %w", sha, err)
			}
			if tree.Truncated {
				return nil, fmt.Errorf("direct tree %q response is truncated; cannot guarantee a complete list", sha)
			}
		}

		for _, entry := range tree.Tree {
			switch entry.Type {
			case "tree":
				if !recursive && entry.SHA != "" {
					if _, exists := queued[entry.SHA]; !exists {
						stack = append(stack, directory{entry.SHA, dir.path + "/" + entry.Path})
						queued[entry.SHA] = struct{}{}
					}
				}
			case "blob":
				name := entry.Path
				if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
					name = name[slash+1:]
				}
				if cveFileNamePattern.MatchString(name) {
					seenNames[strings.TrimSuffix(name, ".json")] = struct{}{}
				}
			}
		}
		if c.progress != nil {
			c.progress.completed++
			c.progress.pending = len(stack)
			c.progress.found = len(seenNames)
		}
		if err := c.progress.report(ctx, "github_traversing", "当前目录读取完成"); err != nil {
			return nil, err
		}
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
		mode := "非递归"
		if recursive {
			mode = "递归"
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
