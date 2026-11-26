package job_handlers

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"ManScan/server/internal/service"
)

const githubReleaseDeltaMaxBytes = 256 << 20

type githubReleaseResponse struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		ID                 int64  `json:"id"`
		URL                string `json:"url"`
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// ListCVEDeltaIDsWithProgress reads the release delta for the requested UTC hour.
func (c *GitHubTreeClient) ListCVEDeltaIDsWithProgress(ctx context.Context, releaseHour time.Time, reporter service.ProgressReporter) ([]string, error) {
	client := *c
	client.progress = &githubTreeProgress{reporter: reporter, directory: "CVE Release 增量包"}
	return client.ListCVEDeltaIDs(ctx, releaseHour)
}

// ListCVEDeltaIDs reads CVE IDs from the release's hourly delta ZIP.
func (c *GitHubTreeClient) ListCVEDeltaIDs(ctx context.Context, releaseHour time.Time) ([]string, error) {
	releaseHour = releaseHour.UTC().Truncate(time.Hour)
	tag := "cve_" + releaseHour.Format("2006-01-02_1504Z")
	assetName := fmt.Sprintf("%s_delta_CVEs_at_%sZ.zip", releaseHour.Format("2006-01-02"), releaseHour.Format("1504"))
	var release githubReleaseResponse
	if err := c.runReleaseRequest(ctx, "正在读取 GitHub CVE Release 元数据", func(requestCtx context.Context) error {
		var err error
		release, err = c.getReleaseOnce(requestCtx, tag)
		return err
	}); err != nil {
		return nil, fmt.Errorf("读取 GitHub Release %q 失败: %w", tag, err)
	}
	if release.TagName != tag {
		return nil, fmt.Errorf("GitHub Release 标签不匹配: 期望 %q，收到 %q", tag, release.TagName)
	}
	var assetURL, assetAPIURL string
	for _, asset := range release.Assets {
		if asset.Name != assetName {
			continue
		}
		if asset.Size < 0 || asset.Size > githubReleaseDeltaMaxBytes {
			return nil, fmt.Errorf("CVE Release 增量包大小无效或超过限制: %d 字节", asset.Size)
		}
		assetURL = asset.BrowserDownloadURL
		expectedAPIURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/assets/%d", c.Owner, c.Repository, asset.ID)
		if asset.ID > 0 && asset.URL == expectedAPIURL {
			assetAPIURL = asset.URL
		}
		break
	}
	if assetURL == "" {
		return nil, fmt.Errorf("GitHub Release %q 缺少增量文件 %q", tag, assetName)
	}
	expectedURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s", c.Owner, c.Repository, tag, assetName)
	if assetURL != expectedURL {
		return nil, errors.New("GitHub Release 增量文件地址与预期不匹配")
	}

	var ids []string
	apiErr := errors.New("Release 缺少有效的官方资产 API 地址")
	if assetAPIURL != "" {
		ids, apiErr = c.readReleaseDelta(ctx, assetAPIURL, true)
	}
	if apiErr != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var progressErr *githubTreeProgressError
		if errors.Is(apiErr, context.Canceled) || errors.As(apiErr, &progressErr) {
			return nil, apiErr
		}
		if err := c.progress.report(ctx, "github_fallback", "GitHub 资产 API 下载未成功，正在切换到 Release 下载链接"); err != nil {
			return nil, err
		}
		var err error
		ids, err = c.readReleaseDelta(ctx, assetURL, false)
		if err != nil {
			return nil, fmt.Errorf("GitHub Release 增量获取失败；资产 API: %w；下载链接: %w", apiErr, err)
		}
	}
	if c.progress != nil {
		c.progress.found = len(ids)
		if err := c.progress.report(ctx, "github_finished", fmt.Sprintf("前一小时 Release 增量读取完成，共 %d 个 CVE", len(ids))); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// readReleaseDelta validates each downloaded ZIP before accepting a download source.
func (c *GitHubTreeClient) readReleaseDelta(ctx context.Context, assetURL string, useAPI bool) ([]string, error) {
	message := "正在通过 Release 下载链接下载 CVE 增量 ZIP"
	if useAPI {
		message = "正在通过 GitHub 资产 API 下载 CVE 增量 ZIP"
	}
	var archivePath string
	err := c.runReleaseRequest(ctx, message, func(requestCtx context.Context) error {
		var downloadErr error
		archivePath, downloadErr = c.downloadReleaseAssetOnce(requestCtx, assetURL, useAPI)
		return downloadErr
	})
	if archivePath != "" {
		defer os.Remove(archivePath)
	}
	if err != nil {
		return nil, fmt.Errorf("下载 GitHub Release 增量文件失败: %w", err)
	}
	ids, err := cveIDsFromDeltaZip(archivePath)
	if err != nil {
		return nil, fmt.Errorf("解析 GitHub Release 增量 ZIP 失败: %w", err)
	}
	return ids, nil
}

func (c *GitHubTreeClient) runReleaseRequest(ctx context.Context, message string, request func(context.Context) error) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.beforeRequest != nil {
			if err := c.progress.run(ctx, "github_waiting", "正在等待 GitHub API Key 请求额度", c.beforeRequest); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		err := c.progress.run(ctx, "github_requesting", fmt.Sprintf("%s，第 %d/%d 次尝试", message, attempt+1, githubTreeMaxAttempts), func(requestCtx context.Context) error {
			return request(requestCtx)
		})
		if err == nil || !retryableGitHubTreeError(err) {
			return err
		}
		if attempt+1 >= githubTreeMaxAttempts {
			return &githubTreeRetryError{err: err}
		}
		if reportErr := c.progress.report(ctx, "github_retrying", fmt.Sprintf("%s，%d 秒后进行第 %d/%d 次尝试", githubTreeRetryReason(err), 1<<attempt, attempt+2, githubTreeMaxAttempts)); reportErr != nil {
			return reportErr
		}
		timer := time.NewTimer(time.Second << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *GitHubTreeClient) getReleaseOnce(ctx context.Context, tag string) (githubReleaseResponse, error) {
	baseURL := strings.TrimRight(c.BaseURL, "/")
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", baseURL, c.Owner, c.Repository, url.PathEscape(tag))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return githubReleaseResponse{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "manscan-cve-release-delta")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if c.progress != nil {
		c.progress.requests.Add(1)
	}
	response, err := client.Do(request)
	if err != nil {
		return githubReleaseResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return githubReleaseResponse{}, fmt.Errorf("GitHub Release %q 不存在", tag)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return githubReleaseResponse{}, fmt.Errorf("GitHub API returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil {
		return githubReleaseResponse{}, err
	}
	if len(body) > 2<<20 {
		return githubReleaseResponse{}, errors.New("GitHub Release 元数据超过大小限制")
	}
	var release githubReleaseResponse
	if err := json.Unmarshal(body, &release); err != nil {
		return githubReleaseResponse{}, fmt.Errorf("decode GitHub Release response: %w", err)
	}
	return release, nil
}

func (c *GitHubTreeClient) downloadReleaseAssetOnce(ctx context.Context, assetURL string, useAPI bool) (string, error) {
	expectedHost := "github.com"
	if useAPI {
		expectedHost = "api.github.com"
	}
	parsed, err := url.Parse(assetURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != expectedHost || parsed.User != nil {
		return "", errors.New("GitHub Release 增量文件地址无效")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/zip")
	request.Header.Set("User-Agent", "manscan-cve-release-delta")
	if useAPI {
		request.Header.Set("Accept", "application/octet-stream")
		request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.Token != "" {
			request.Header.Set("Authorization", "Bearer "+c.Token)
		}
	}
	baseClient := c.HTTPClient
	if baseClient == nil {
		baseClient = http.DefaultClient
	}
	downloadClient := *baseClient
	downloadClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("GitHub Release 下载重定向次数过多")
		}
		if request.URL.Scheme != "https" || request.URL.User != nil {
			return errors.New("GitHub Release 下载拒绝非 HTTPS 重定向")
		}
		host := request.URL.Host
		if !allowedGitHubReleaseRedirect(host) && !(useAPI && host == "api.github.com") {
			return fmt.Errorf("GitHub Release 下载拒绝重定向到未允许的主机 %q", host)
		}
		// The token is only needed by the API, never by public asset hosts.
		if host != "api.github.com" {
			request.Header.Del("Authorization")
		}
		return nil
	}
	if c.progress != nil {
		c.progress.requests.Add(1)
	}
	response, err := downloadClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("GitHub Release asset returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > githubReleaseDeltaMaxBytes {
		return "", errors.New("CVE Release 增量 ZIP 超过大小限制")
	}
	file, err := os.CreateTemp("", "manscan-cve-delta-*.zip")
	if err != nil {
		return "", fmt.Errorf("创建临时 Release 文件失败: %w", err)
	}
	archivePath := file.Name()
	keepFile := false
	defer func() {
		_ = file.Close()
		if !keepFile {
			_ = os.Remove(archivePath)
		}
	}()
	var reader io.Reader = response.Body
	if c.progress != nil {
		reader = githubTreeProgressReader{reader: reader, progress: c.progress}
	}
	size, err := io.Copy(file, io.LimitReader(reader, githubReleaseDeltaMaxBytes+1))
	if err != nil {
		return "", err
	}
	if size > githubReleaseDeltaMaxBytes {
		return "", errors.New("CVE Release 增量 ZIP 超过大小限制")
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("关闭临时 Release 文件失败: %w", err)
	}
	keepFile = true
	return archivePath, nil
}

func cveIDsFromDeltaZip(archivePath string) ([]string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	archive, err := zip.NewReader(file, stat.Size())
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		name := path.Clean(entry.Name)
		if path.Dir(name) != "deltaCves" {
			continue
		}
		name = path.Base(name)
		if !cveFileNamePattern.MatchString(name) {
			continue
		}
		seen[strings.TrimSuffix(name, ".json")] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func allowedGitHubReleaseRedirect(host string) bool {
	switch strings.ToLower(host) {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	default:
		return false
	}
}
