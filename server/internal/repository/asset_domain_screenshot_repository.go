package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ManScan/server/internal/model/dto"
)

const (
	maxAssetDomainScreenshotSize      = 20 << 20
	maxAssetDomainScreenshotPageBytes = 64 << 20
)

var (
	ErrAssetDomainScreenshotNotFound     = errors.New("域名资产截图不存在")
	ErrAssetDomainScreenshotTooLarge     = errors.New("域名资产截图文件过大")
	ErrAssetDomainScreenshotPageTooLarge = errors.New("域名资产截图分页数据过大")
	ErrUnsupportedAssetDomainScreenshot  = errors.New("域名资产截图格式不受支持")
)

// AssetDomainScreenshotRepository reads domain asset screenshots from storage.
type AssetDomainScreenshotRepository interface {
	Latest(ctx context.Context, domain string) (*AssetDomainScreenshotRecord, error)
	List(ctx context.Context, domain string, page, pageSize int) (*dto.PageResult[AssetDomainScreenshotRecord], error)
}

// AssetDomainScreenshotRecord contains a screenshot read from storage.
type AssetDomainScreenshotRecord struct {
	Domain       string
	CapturedDate time.Time
	FileName     string
	ContentType  string
	Image        []byte
}

type assetDomainScreenshotRepository struct {
	directory string
}

type assetDomainScreenshotMetadata struct {
	capturedDate time.Time
	fileName     string
}

// NewAssetDomainScreenshotRepository creates a filesystem screenshot repository.
func NewAssetDomainScreenshotRepository(directory string) AssetDomainScreenshotRepository {
	return &assetDomainScreenshotRepository{directory: filepath.Clean(directory)}
}

// Latest returns the screenshot with the newest date for a domain asset.
func (r *assetDomainScreenshotRepository) Latest(ctx context.Context, domain string) (*AssetDomainScreenshotRecord, error) {
	items, err := r.listMetadata(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrAssetDomainScreenshotNotFound
	}
	return r.read(ctx, domain, items[0])
}

// List returns one page of screenshots ordered by capture date descending.
func (r *assetDomainScreenshotRepository) List(ctx context.Context, domain string, page, pageSize int) (*dto.PageResult[AssetDomainScreenshotRecord], error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}

	metadata, err := r.listMetadata(ctx, domain)
	if err != nil {
		return nil, err
	}
	total := len(metadata)
	totalPages := 0
	if total > 0 {
		totalPages = (total-1)/pageSize + 1
	}

	if total == 0 || page > totalPages {
		return &dto.PageResult[AssetDomainScreenshotRecord]{
			Page: page, PageSize: pageSize, Total: total, TotalPages: totalPages, Items: []AssetDomainScreenshotRecord{},
		}, nil
	}
	start := (page - 1) * pageSize
	end := total
	if pageSize < total-start {
		end = start + pageSize
	}
	items := make([]AssetDomainScreenshotRecord, 0, end-start)
	totalBytes := 0
	for _, item := range metadata[start:end] {
		record, readErr := r.read(ctx, domain, item)
		if readErr != nil {
			return nil, readErr
		}
		totalBytes += len(record.Image)
		if totalBytes > maxAssetDomainScreenshotPageBytes {
			return nil, ErrAssetDomainScreenshotPageTooLarge
		}
		items = append(items, *record)
	}

	return &dto.PageResult[AssetDomainScreenshotRecord]{
		Page: page, PageSize: pageSize, Total: total, TotalPages: totalPages, Items: items,
	}, nil
}

func (r *assetDomainScreenshotRepository) listMetadata(ctx context.Context, domain string) ([]assetDomainScreenshotMetadata, error) {
	entries, err := os.ReadDir(r.directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []assetDomainScreenshotMetadata{}, nil
		}
		return nil, fmt.Errorf("读取截图目录失败: %w", err)
	}

	prefix := strings.ReplaceAll(domain, "/", "_") + "_"
	items := make([]assetDomainScreenshotMetadata, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		rawExtension := filepath.Ext(entry.Name())
		extension := strings.ToLower(rawExtension)
		if !isSupportedScreenshotExtension(extension) {
			continue
		}
		dateValue := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), prefix), rawExtension)
		if len(dateValue) != len("20060102") {
			continue
		}
		capturedDate, parseErr := time.Parse("20060102", dateValue)
		if parseErr != nil {
			continue
		}
		items = append(items, assetDomainScreenshotMetadata{capturedDate: capturedDate, fileName: entry.Name()})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].capturedDate.Equal(items[j].capturedDate) {
			return items[i].fileName > items[j].fileName
		}
		return items[i].capturedDate.After(items[j].capturedDate)
	})
	return items, nil
}

func (r *assetDomainScreenshotRepository) read(ctx context.Context, domain string, item assetDomainScreenshotMetadata) (*AssetDomainScreenshotRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	image, err := readAssetDomainScreenshotFile(r.directory, item.fileName)
	if err != nil {
		return nil, err
	}
	contentType := http.DetectContentType(image)
	if !isSupportedScreenshotContentType(contentType) {
		return nil, ErrUnsupportedAssetDomainScreenshot
	}

	return &AssetDomainScreenshotRecord{
		Domain:       domain,
		CapturedDate: item.capturedDate,
		FileName:     item.fileName,
		ContentType:  contentType,
		Image:        image,
	}, nil
}

func readAssetDomainScreenshotFile(directory, fileName string) (image []byte, resultErr error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("打开截图目录失败: %w", err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("关闭截图目录失败: %w", closeErr))
		}
	}()

	file, err := root.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("打开截图文件失败: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("关闭截图文件失败: %w", closeErr))
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("读取截图文件信息失败: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrUnsupportedAssetDomainScreenshot
	}
	if info.Size() > maxAssetDomainScreenshotSize {
		return nil, ErrAssetDomainScreenshotTooLarge
	}

	image, err = io.ReadAll(io.LimitReader(file, maxAssetDomainScreenshotSize+1))
	if err != nil {
		return nil, fmt.Errorf("读取截图文件失败: %w", err)
	}
	if len(image) > maxAssetDomainScreenshotSize {
		return nil, ErrAssetDomainScreenshotTooLarge
	}
	return image, nil
}

func isSupportedScreenshotExtension(extension string) bool {
	switch extension {
	case ".png", ".jpg", ".jpeg", ".webp":
		return true
	default:
		return false
	}
}

func isSupportedScreenshotContentType(contentType string) bool {
	switch contentType {
	case "image/png", "image/jpeg", "image/webp":
		return true
	default:
		return false
	}
}
