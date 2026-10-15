package repository

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

var testPNGImage = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
}

func TestAssetDomainScreenshotRepositoryLatestUsesNewestDate(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeScreenshotTestFile(t, directory, "http:__app.example.com_20261014.png", testPNGImage)
	writeScreenshotTestFile(t, directory, "http:__app.example.com_20261015.PNG", testPNGImage)
	writeScreenshotTestFile(t, directory, "http:__app.example.com_invalid.png", testPNGImage)
	writeScreenshotTestFile(t, directory, "http:__other.example.com_20261016.png", testPNGImage)
	writeScreenshotTestFile(t, directory, "http:__app.example.com_20261016.txt", testPNGImage)

	repository := NewAssetDomainScreenshotRepository(directory)
	item, err := repository.Latest(context.Background(), "http://app.example.com")
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if item.FileName != "http:__app.example.com_20261015.PNG" {
		t.Fatalf("FileName = %q, want newest screenshot", item.FileName)
	}
	if item.CapturedDate.Format("2006-01-02") != "2026-10-15" {
		t.Fatalf("CapturedDate = %s, want 2026-10-15", item.CapturedDate)
	}
	if item.ContentType != "image/png" {
		t.Fatalf("ContentType = %q, want image/png", item.ContentType)
	}
}

func TestAssetDomainScreenshotRepositoryListPaginatesDescending(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for _, date := range []string{"20261013", "20261014", "20261015"} {
		writeScreenshotTestFile(t, directory, "app.example.com_"+date+".png", testPNGImage)
	}

	repository := NewAssetDomainScreenshotRepository(directory)
	page, err := repository.List(context.Background(), "app.example.com", 2, 2)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if page.Page != 2 || page.PageSize != 2 || page.Total != 3 || page.TotalPages != 2 {
		t.Fatalf("page metadata = %+v, want page=2 pageSize=2 total=3 totalPages=2", page)
	}
	if len(page.Items) != 1 || page.Items[0].CapturedDate.Format("20060102") != "20261013" {
		t.Fatalf("items = %+v, want only 20261013", page.Items)
	}

	emptyPage, err := repository.List(context.Background(), "app.example.com", math.MaxInt, 20)
	if err != nil {
		t.Fatalf("List() with large page error = %v", err)
	}
	if len(emptyPage.Items) != 0 || emptyPage.Total != 3 {
		t.Fatalf("large page = %+v, want empty items with total 3", emptyPage)
	}
}

func TestAssetDomainScreenshotRepositoryHandlesMissingAndUnsafeFiles(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	repository := NewAssetDomainScreenshotRepository(directory)
	if _, err := repository.Latest(context.Background(), "missing.example.com"); !errors.Is(err, ErrAssetDomainScreenshotNotFound) {
		t.Fatalf("Latest() error = %v, want ErrAssetDomainScreenshotNotFound", err)
	}

	writeScreenshotTestFile(t, directory, "app.example.com_20261015.png", []byte("<html>not an image</html>"))
	if _, err := repository.Latest(context.Background(), "app.example.com"); !errors.Is(err, ErrUnsupportedAssetDomainScreenshot) {
		t.Fatalf("Latest() error = %v, want ErrUnsupportedAssetDomainScreenshot", err)
	}

	if err := os.Remove(filepath.Join(directory, "app.example.com_20261015.png")); err != nil {
		t.Fatalf("remove invalid screenshot: %v", err)
	}
	largePath := filepath.Join(directory, "app.example.com_20261015.png")
	file, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("create large screenshot: %v", err)
	}
	if err := file.Truncate(maxAssetDomainScreenshotSize + 1); err != nil {
		file.Close()
		t.Fatalf("truncate large screenshot: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close large screenshot: %v", err)
	}
	if _, err := repository.Latest(context.Background(), "app.example.com"); !errors.Is(err, ErrAssetDomainScreenshotTooLarge) {
		t.Fatalf("Latest() error = %v, want ErrAssetDomainScreenshotTooLarge", err)
	}
}

func writeScreenshotTestFile(t *testing.T, directory, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
		t.Fatalf("write screenshot %s: %v", name, err)
	}
}
