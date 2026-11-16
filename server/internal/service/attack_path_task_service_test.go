package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type fakeAttackPathClassifier struct{}

func (fakeAttackPathClassifier) Process(ctx context.Context, input io.Reader, output *os.File, total int, progress func(context.Context, int, int) error) (int, int, error) {
	scanner := bufio.NewScanner(input)
	processed, kept := 0, 0
	for scanner.Scan() {
		path := scanner.Text()
		processed++
		if !strings.Contains(path, "../") && !strings.Contains(path, "union select") {
			if _, err := io.WriteString(output, path+"\n"); err != nil {
				return processed, kept, err
			}
			kept++
		}
		if err := progress(ctx, processed, kept); err != nil {
			return processed, kept, err
		}
	}
	return processed, kept, scanner.Err()
}

func TestAttackPathTaskServiceDeduplicatesAndFiltersTXT(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:attack-path-task?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&entity.AttackPathTask{}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	svc := NewAttackPathTaskService(repository.NewAttackPathTaskRepository(db), fakeAttackPathClassifier{}, nil, root)
	ctx := context.Background()
	created, err := svc.Create(ctx, 7, strings.NewReader("/api/users\n/api/users\n/../../etc/passwd\n/api/orders\n"))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Total != 3 || created.Status != "queued" {
		t.Fatalf("created task = %+v, want 3 unique paths queued", created)
	}
	if _, err := svc.Get(ctx, 8, created.ID); err == nil {
		t.Fatal("Get() succeeded for another user's task")
	}
	if _, _, err := svc.Download(ctx, 8, created.ID); err == nil {
		t.Fatal("Download() succeeded for another user's task")
	}
	if _, err := svc.Cancel(ctx, 8, created.ID); err == nil {
		t.Fatal("Cancel() succeeded for another user's task")
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	go svc.Run(workerCtx)
	defer stopWorker()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, err := svc.Get(ctx, 7, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status == "completed" {
			output, _, err := svc.Download(ctx, 7, created.ID)
			if err != nil {
				t.Fatal(err)
			}
			text, err := io.ReadAll(output)
			_ = output.Close()
			if err != nil {
				t.Fatal(err)
			}
			if string(text) != "/api/users\n/api/orders\n" || current.Kept != 2 || current.Processed != 3 {
				t.Fatalf("task result = (%q, %+v), want clean stable-order deduplicated paths", text, current)
			}
			files, err := filepath.Glob(filepath.Join(root, "data", "attack-path-tasks", created.ID, "output.*.txt"))
			if err != nil || len(files) != 1 {
				t.Fatalf("expected one result file, got %v: %v", files, err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("task did not complete before timeout")
}

func TestParseAttackPathTXTValidatesAndDeduplicates(t *testing.T) {
	file := filepath.Join(t.TempDir(), "input.txt")
	count, err := writeUniqueAttackPaths(context.Background(), file, strings.NewReader("\xef\xbb\xbf/api/a\r\n\n/api/a\r\n/api/b\n"))
	if err != nil {
		t.Fatalf("writeUniqueAttackPaths() error = %v", err)
	}
	text, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || string(text) != "/api/a\n/api/b\n" {
		t.Fatalf("parsed paths = %q count %d", text, count)
	}
	if _, err := writeUniqueAttackPaths(context.Background(), filepath.Join(t.TempDir(), "invalid.txt"), strings.NewReader("\xff")); err == nil {
		t.Fatal("invalid UTF-8 input was accepted")
	}
}

type countingAttackPathClassifier struct{ calls atomic.Int32 }

func (c *countingAttackPathClassifier) Process(ctx context.Context, input io.Reader, output *os.File, total int, progress func(context.Context, int, int) error) (int, int, error) {
	c.calls.Add(1)
	return (fakeAttackPathClassifier{}).Process(ctx, input, output, total, progress)
}

func TestAttackPathTaskServiceLargeFileStaysOnDisk(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "large-task.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.AttackPathTask{}); err != nil {
		t.Fatal(err)
	}
	if db.Migrator().HasColumn(&entity.AttackPathTask{}, "input_text") || db.Migrator().HasColumn(&entity.AttackPathTask{}, "output_text") {
		t.Fatal("task schema still contains legacy text columns")
	}
	root := t.TempDir()
	classifier := &countingAttackPathClassifier{}
	svc := NewAttackPathTaskService(repository.NewAttackPathTaskRepository(db), classifier, nil, root).(*attackPathTaskService)
	var input strings.Builder
	for index := 0; index < 1020; index++ {
		fmt.Fprintf(&input, "/api/item/%d\n", index)
	}
	created, err := svc.Create(context.Background(), 7, strings.NewReader(input.String()))
	if err != nil {
		t.Fatal(err)
	}
	var stored entity.AttackPathTask
	if err := db.First(&stored, "id = ?", created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Total != 1020 {
		t.Fatalf("unexpected stored task: %+v", stored)
	}
	svc.processNext(context.Background())
	if classifier.calls.Load() != 1 {
		t.Fatalf("file processor calls = %d, want 1", classifier.calls.Load())
	}
	var completed entity.AttackPathTask
	if err := db.First(&completed, "id = ?", created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if completed.Status != "completed" || completed.Processed != 1020 || completed.Kept != 1020 || completed.OutputFileName == "" {
		t.Fatalf("unexpected completed task: %+v", completed)
	}
	file, size, err := svc.Download(context.Background(), 7, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result, err := io.ReadAll(file)
	if err != nil || size != int64(input.Len()) || string(result) != input.String() {
		t.Fatalf("result mismatch: size=%d err=%v", size, err)
	}
}

type failingAttackPathReader struct{}

func (failingAttackPathReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestAttackPathTaskServiceCleansFailedUpload(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "upload-failure.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.AttackPathTask{}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	svc := NewAttackPathTaskService(repository.NewAttackPathTaskRepository(db), fakeAttackPathClassifier{}, nil, root)
	if _, err := svc.Create(context.Background(), 7, failingAttackPathReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Create() error = %v, want input read failure", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "data", "attack-path-tasks"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed upload left task files: %v, err=%v", entries, err)
	}
}

type failingAttackPathClassifier struct{}

func (failingAttackPathClassifier) Process(context.Context, io.Reader, *os.File, int, func(context.Context, int, int) error) (int, int, error) {
	return 0, 0, errors.New("model unavailable")
}

func TestAttackPathTaskServiceFailedTaskHasNoDownload(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "model-failure.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.AttackPathTask{}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	svc := NewAttackPathTaskService(repository.NewAttackPathTaskRepository(db), failingAttackPathClassifier{}, nil, root).(*attackPathTaskService)
	created, err := svc.Create(context.Background(), 7, strings.NewReader("/api/a\n"))
	if err != nil {
		t.Fatal(err)
	}
	svc.processNext(context.Background())
	current, err := svc.Get(context.Background(), 7, created.ID)
	if err != nil || current.Status != "failed" {
		t.Fatalf("failed task status = %+v, err=%v", current, err)
	}
	if _, _, err := svc.Download(context.Background(), 7, created.ID); !errors.Is(err, ErrAttackPathNotReady) {
		t.Fatalf("Download() error = %v, want not ready", err)
	}
	files, err := filepath.Glob(filepath.Join(root, "data", "attack-path-tasks", created.ID, "output.*.txt"))
	if err != nil || len(files) != 0 {
		t.Fatalf("failed task left output files: %v, err=%v", files, err)
	}
}

func TestAttackPathTaskServiceRequiresInputFile(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "missing-input.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.AttackPathTask{}); err != nil {
		t.Fatal(err)
	}
	classifier := &countingAttackPathClassifier{}
	svc := NewAttackPathTaskService(repository.NewAttackPathTaskRepository(db), classifier, nil, t.TempDir()).(*attackPathTaskService)
	ctx := context.Background()
	created, err := svc.Create(ctx, 7, strings.NewReader("/api/a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(svc.taskDir(created.ID), "input.txt")); err != nil {
		t.Fatal(err)
	}
	svc.processNext(ctx)
	current, err := svc.Get(ctx, 7, created.ID)
	if err != nil || current.Status != "failed" || current.Processed != 0 || classifier.calls.Load() != 0 {
		t.Fatalf("missing input result = %+v, error=%v, processor calls=%d", current, err, classifier.calls.Load())
	}
	if _, _, err := svc.Download(ctx, 7, created.ID); !errors.Is(err, ErrAttackPathNotReady) {
		t.Fatalf("Download() error = %v, want not ready", err)
	}
}

func TestAttackPathTaskServiceDownloadsOnlyResultFiles(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "download-files.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.AttackPathTask{}); err != nil {
		t.Fatal(err)
	}
	svc := NewAttackPathTaskService(repository.NewAttackPathTaskRepository(db), fakeAttackPathClassifier{}, nil, t.TempDir()).(*attackPathTaskService)
	fileName := "output." + strings.Repeat("a", 32) + ".txt"
	for _, tc := range []struct {
		name       string
		fileName   string
		createFile bool
		content    string
		wantErr    error
	}{
		{name: "no file reference", wantErr: ErrInvalidAttackPathInput},
		{name: "inline text", fileName: "/api/users\n", wantErr: ErrInvalidAttackPathInput},
		{name: "path traversal", fileName: "../" + fileName, wantErr: ErrInvalidAttackPathInput},
		{name: "missing file", fileName: fileName, wantErr: os.ErrNotExist},
		{name: "empty result", fileName: fileName, createFile: true},
		{name: "normal result", fileName: fileName, createFile: true, content: "/api/users\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := randomAttackPathID()
			if err != nil {
				t.Fatal(err)
			}
			task := &entity.AttackPathTask{ID: id, OwnerUserID: 7, Status: "completed", OutputFileName: tc.fileName, Total: 1, Processed: 1}
			if err := svc.repo.Create(context.Background(), task); err != nil {
				t.Fatal(err)
			}
			if tc.createFile {
				if err := os.MkdirAll(svc.taskDir(id), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(svc.taskDir(id), tc.fileName), []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			file, size, err := svc.Download(context.Background(), 7, id)
			if file != nil {
				defer file.Close()
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || file != nil {
					t.Fatalf("Download() error=%v, want %v and no file", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(file)
			if err != nil || string(content) != tc.content || size != int64(len(tc.content)) {
				t.Fatalf("download content=%q, size=%d, error=%v", content, size, err)
			}
		})
	}
}
