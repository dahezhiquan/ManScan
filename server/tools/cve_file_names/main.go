// Command cve_file_names lists CVE file names from the cvelistV5 repository
// without cloning the repository or downloading file contents.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultAPIBaseURL = "https://api.github.com"
	defaultOwner      = "CVEProject"
	defaultRepository = "cvelistV5"
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

// GitHubTreeClient reads GitHub Git Tree metadata for one repository.
type GitHubTreeClient struct {
	HTTPClient *http.Client
	BaseURL    string
	Owner      string
	Repository string
	Token      string
}

// NewGitHubTreeClient creates a client for the CVEProject/cvelistV5 repository.
func NewGitHubTreeClient(token string) *GitHubTreeClient {
	return &GitHubTreeClient{
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		BaseURL:    defaultAPIBaseURL,
		Owner:      defaultOwner,
		Repository: defaultRepository,
		Token:      token,
	}
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

	var stack []string
	for _, entry := range root.Tree {
		if entry.Type == "tree" && entry.Path == "cves" && entry.SHA != "" {
			stack = append(stack, entry.SHA)
		}
	}
	if len(stack) == 0 {
		return nil, errors.New("repository tree does not contain a cves directory")
	}

	seenTrees := make(map[string]struct{})
	seenNames := make(map[string]struct{})
	for len(stack) > 0 {
		last := len(stack) - 1
		sha := stack[last]
		stack = stack[:last]
		if _, seen := seenTrees[sha]; seen {
			continue
		}
		seenTrees[sha] = struct{}{}

		// Recursive trees reduce request volume. A truncated result is discarded
		// and replaced by a direct listing so every subtree is still visited.
		recursive := true
		tree, err := c.getTree(ctx, sha, recursive)
		if err != nil {
			return nil, fmt.Errorf("read tree %q: %w", sha, err)
		}
		if tree.Truncated {
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
					stack = append(stack, entry.SHA)
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
	}

	names := make([]string, 0, len(seenNames))
	for name := range seenNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (c *GitHubTreeClient) getTree(ctx context.Context, ref string, recursive bool) (treeResponse, error) {
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
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(&tree); err != nil {
		return treeResponse{}, fmt.Errorf("decode GitHub tree response: %w", err)
	}
	if tree.Tree == nil {
		return treeResponse{}, errors.New("GitHub tree response is missing the tree array")
	}
	return tree, nil
}

func main() {
	ref := flag.String("ref", "main", "GitHub branch, tag, or commit SHA")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments; use -ref to select a branch, tag, or commit SHA")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	names, err := NewGitHubTreeClient(os.Getenv("GITHUB_TOKEN")).ListCVEFileNames(ctx, *ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list CVE file names: %v\n", err)
		os.Exit(1)
	}

	writer := bufio.NewWriter(os.Stdout)
	for _, name := range names {
		if _, err := fmt.Fprintln(writer, name); err != nil {
			fmt.Fprintf(os.Stderr, "write CVE file name: %v\n", err)
			os.Exit(1)
		}
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush CVE file names: %v\n", err)
		os.Exit(1)
	}
}
