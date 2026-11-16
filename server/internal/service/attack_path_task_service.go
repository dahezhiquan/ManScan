package service

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/repository"

	"gorm.io/gorm"
)

const (
	attackPathMaxBytes = 1 << 30
	attackPathMaxLines = 500000
)

var (
	ErrInvalidAttackPathInput = errors.New("TXT 内容不合法")
	ErrAttackPathNotReady     = errors.New("结果尚未生成")
	ErrAttackPathUnavailable  = errors.New("攻击路径识别服务未配置")
)

// AttackPathFileProcessor orchestrates file tools for an entire TXT task.
type AttackPathFileProcessor interface {
	Process(context.Context, io.Reader, *os.File, int, func(context.Context, int, int) error) (int, int, error)
}

type AttackPathTaskService interface {
	Create(ctx context.Context, ownerID int64, input io.Reader) (*dto.AttackPathTaskResponse, error)
	Get(ctx context.Context, ownerID int64, id string) (*dto.AttackPathTaskResponse, error)
	Download(ctx context.Context, ownerID int64, id string) (io.ReadCloser, int64, error)
	Cancel(ctx context.Context, ownerID int64, id string) (*dto.AttackPathTaskResponse, error)
	Run(ctx context.Context)
}

type attackPathTaskService struct {
	repo      repository.AttackPathTaskRepository
	processor AttackPathFileProcessor
	logger    *logx.Logger
	rootDir   string
}

// NewAttackPathTaskService creates the asynchronous filter service.
func NewAttackPathTaskService(repo repository.AttackPathTaskRepository, processor AttackPathFileProcessor, logger *logx.Logger, rootDir string) AttackPathTaskService {
	return &attackPathTaskService{repo: repo, processor: processor, logger: logger, rootDir: rootDir}
}

func (s *attackPathTaskService) Create(ctx context.Context, ownerID int64, input io.Reader) (*dto.AttackPathTaskResponse, error) {
	if s.processor == nil {
		return nil, ErrAttackPathUnavailable
	}
	if input == nil || ownerID <= 0 {
		return nil, ErrInvalidAttackPathInput
	}
	if s.rootDir == "" {
		return nil, ErrAttackPathUnavailable
	}
	id, err := randomAttackPathID()
	if err != nil {
		return nil, err
	}
	dir := s.taskDir(id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	total, err := writeUniqueAttackPaths(ctx, filepath.Join(dir, "input.txt"), input)
	if err != nil {
		return nil, err
	}
	task := &entity.AttackPathTask{ID: id, OwnerUserID: ownerID, Status: "queued", Total: total}
	if err = s.repo.Create(ctx, task); err != nil {
		return nil, err
	}
	return attackPathTaskResponse(task), nil
}

func (s *attackPathTaskService) Get(ctx context.Context, ownerID int64, id string) (*dto.AttackPathTaskResponse, error) {
	task, err := s.repo.FindOwned(ctx, id, ownerID)
	if err != nil {
		return nil, err
	}
	return attackPathTaskResponse(task), nil
}

func (s *attackPathTaskService) Download(ctx context.Context, ownerID int64, id string) (io.ReadCloser, int64, error) {
	task, err := s.repo.FindOutputOwned(ctx, id, ownerID)
	if err != nil {
		return nil, 0, err
	}
	if task.Status != "completed" {
		return nil, 0, ErrAttackPathNotReady
	}
	if s.rootDir == "" {
		return nil, 0, ErrAttackPathUnavailable
	}
	if !validAttackPathID(id) {
		return nil, 0, ErrInvalidAttackPathInput
	}
	if name, valid := attackPathOutputName(task.OutputFileName); valid {
		file, err := os.Open(filepath.Join(s.taskDir(id), name))
		if err != nil {
			return nil, 0, err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, 0, err
		}
		return file, info.Size(), nil
	}
	return nil, 0, ErrInvalidAttackPathInput
}

func attackPathOutputName(value string) (string, bool) {
	if !strings.HasPrefix(value, "output.") || !strings.HasSuffix(value, ".txt") {
		return "", false
	}
	if len(value) != len("output.")+32+len(".txt") {
		return "", false
	}
	_, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, "output."), ".txt"))
	return value, err == nil
}

func (s *attackPathTaskService) Cancel(ctx context.Context, ownerID int64, id string) (*dto.AttackPathTaskResponse, error) {
	if _, err := s.repo.FindOwned(ctx, id, ownerID); err != nil {
		return nil, err
	}
	if _, err := s.repo.Cancel(ctx, id, ownerID); err != nil {
		return nil, err
	}
	return s.Get(ctx, ownerID, id)
}

// Run polls the database queue until the server shuts down.
func (s *attackPathTaskService) Run(ctx context.Context) {
	if s.processor == nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		s.processNext(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *attackPathTaskService) processNext(ctx context.Context) {
	token, err := randomAttackPathID()
	if err != nil {
		s.logError("生成攻击路径任务租约失败", err)
		return
	}
	task, err := s.repo.ClaimNext(ctx, token, time.Now())
	if errors.Is(err, gorm.ErrRecordNotFound) || ctx.Err() != nil {
		return
	}
	if err != nil {
		s.logError("领取攻击路径任务失败", err)
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if err := s.repo.Renew(runCtx, task.ID, token, time.Now().Add(45*time.Second)); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	output, processed, kept, runErr := s.filter(runCtx, task, token)
	cancel()
	<-done
	if ctx.Err() != nil {
		if name, valid := attackPathOutputName(output); valid {
			_ = os.Remove(filepath.Join(s.taskDir(task.ID), name))
		}
		return
	}
	status, message := "completed", ""
	if runErr != nil {
		status, output, message = "failed", "", "模型识别失败，请稍后重试"
		s.logError("攻击路径任务处理失败", runErr)
	}
	if finishErr := s.repo.Finish(ctx, task.ID, token, status, output, message, processed, kept); finishErr != nil {
		if !errors.Is(finishErr, gorm.ErrRecordNotFound) {
			s.logError("保存攻击路径任务结果失败", finishErr)
		}
		// A database error can occur after commit. Preserve the result until its
		// final status is known, or the completed task may point to a deleted file.
		if name, valid := attackPathOutputName(output); valid && errors.Is(finishErr, gorm.ErrRecordNotFound) {
			_ = os.Remove(filepath.Join(s.taskDir(task.ID), name))
		}
	}
}

func (s *attackPathTaskService) filter(ctx context.Context, task *entity.AttackPathTask, token string) (string, int, int, error) {
	if !validAttackPathID(task.ID) || !validAttackPathID(token) {
		return "", 0, 0, ErrInvalidAttackPathInput
	}
	if err := os.MkdirAll(s.taskDir(task.ID), 0700); err != nil {
		return "", 0, 0, err
	}
	input, err := os.Open(filepath.Join(s.taskDir(task.ID), "input.txt"))
	if err != nil {
		return "", 0, 0, err
	}
	defer input.Close()
	name := "output." + token + ".txt"
	output, err := os.OpenFile(filepath.Join(s.taskDir(task.ID), name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", 0, 0, err
	}
	defer func() { _ = output.Close() }()
	keepOutput := false
	defer func() {
		if !keepOutput {
			_ = os.Remove(output.Name())
		}
	}()
	processed, kept, err := s.processor.Process(ctx, input, output, task.Total, func(progressCtx context.Context, processed, kept int) error {
		return s.repo.UpdateProgress(progressCtx, task.ID, token, processed, kept)
	})
	if err != nil {
		return "", processed, kept, err
	}
	if processed != task.Total || kept < 0 || kept > processed {
		return "", processed, kept, errors.New("文件处理结果计数不合法")
	}
	if err = output.Sync(); err != nil {
		return "", processed, kept, err
	}
	if err = output.Close(); err != nil {
		return "", processed, kept, err
	}
	// Each attempt keeps its own finished inode until the database lease commits.
	if ctx.Err() != nil {
		return "", processed, kept, ctx.Err()
	}
	keepOutput = true
	return name, processed, kept, nil
}

func (s *attackPathTaskService) logError(message string, err error) {
	if s.logger != nil {
		s.logger.Error(message, "error", err)
	}
}

func (s *attackPathTaskService) taskDir(id string) string {
	return filepath.Join(s.rootDir, "data", "attack-path-tasks", id)
}

func validAttackPathID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func writeUniqueAttackPaths(ctx context.Context, target string, input io.Reader) (int, error) {
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	// Fixed-size fingerprints keep deduplication memory bounded for long paths.
	seen := make(map[[sha256.Size]byte]struct{})
	limited := &io.LimitedReader{R: input, N: attackPathMaxBytes + 1}
	reader := bufio.NewReaderSize(limited, 4096)
	total := 0
	firstLine := true
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return 0, ErrInvalidAttackPathInput
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return 0, readErr
		}
		if errors.Is(readErr, io.EOF) && len(line) == 0 {
			break
		}
		path := strings.TrimSpace(string(line))
		if firstLine {
			path = strings.TrimPrefix(path, "\uFEFF")
			firstLine = false
		}
		if path != "" {
			if len(path) > 2048 || !utf8.ValidString(path) || strings.ContainsAny(path, "\r\n\x00") {
				return 0, ErrInvalidAttackPathInput
			}
			fingerprint := sha256.Sum256([]byte(path))
			if _, exists := seen[fingerprint]; !exists {
				seen[fingerprint] = struct{}{}
				total++
				if total > attackPathMaxLines {
					return 0, ErrInvalidAttackPathInput
				}
				if _, err := writer.WriteString(path + "\n"); err != nil {
					return 0, err
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if limited.N == 0 || total == 0 {
		return 0, ErrInvalidAttackPathInput
	}
	if err := writer.Flush(); err != nil {
		return 0, err
	}
	if err := file.Sync(); err != nil {
		return 0, err
	}
	if err := file.Close(); err != nil {
		return 0, err
	}
	return total, nil
}

func randomAttackPathID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("生成任务 ID 失败: %w", err)
	}
	return hex.EncodeToString(bytes[:]), nil
}

func attackPathTaskResponse(task *entity.AttackPathTask) *dto.AttackPathTaskResponse {
	return &dto.AttackPathTaskResponse{ID: task.ID, Status: task.Status, Total: task.Total, Processed: task.Processed, Kept: task.Kept, ErrorMessage: task.ErrorMessage, CreatedAt: task.CreatedAt, FinishedAt: task.FinishedAt}
}
