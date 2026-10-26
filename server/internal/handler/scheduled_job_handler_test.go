package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ManScan/server/internal/middleware"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type scheduledJobControlStub struct {
	service.ScheduledJobService
	err    error
	called bool
	count  int
	output *dto.ScheduledJobRunOutput
}

func (s *scheduledJobControlStub) Stop(context.Context, int64) (int, error) {
	s.called = true
	return s.count, s.err
}

func (s *scheduledJobControlStub) GetRunOutput(context.Context, int64) (*dto.ScheduledJobRunOutput, error) {
	return s.output, s.err
}

func TestScheduledJobStopHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		role   string
		id     string
		err    error
		status int
		called bool
		count  int
	}{
		{name: "admin", role: "admin", id: "1", status: http.StatusAccepted, called: true, count: 2},
		{name: "idle", role: "admin", id: "1", status: http.StatusAccepted, called: true},
		{name: "non-admin", role: "user", id: "1", status: http.StatusForbidden},
		{name: "invalid-id", role: "admin", id: "0", status: http.StatusBadRequest},
		{name: "missing", role: "admin", id: "1", err: gorm.ErrRecordNotFound, status: http.StatusNotFound, called: true},
		{name: "database-error", role: "admin", id: "1", err: errors.New("secret SQL error"), status: http.StatusInternalServerError, called: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &scheduledJobControlStub{err: tc.err, count: tc.count}
			h := NewScheduledJobHandler(stub)
			router := gin.New()
			router.Use(func(c *gin.Context) { c.Set(middleware.ContextUserRoleKey, tc.role) })
			router.POST("/scheduled-jobs/:id/stop", h.Stop)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/scheduled-jobs/"+tc.id+"/stop", nil))
			status := tc.status
			if recorder.Code != status || stub.called != tc.called || strings.Contains(recorder.Body.String(), "secret SQL") {
				t.Fatalf("status=%d, called=%v, body=%s", recorder.Code, stub.called, recorder.Body.String())
			}
			if status == http.StatusAccepted {
				var body struct {
					Data map[string]json.RawMessage `json:"data"`
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				var count int
				if err := json.Unmarshal(body.Data["cancel_requested_runs"], &count); err != nil || count != tc.count {
					t.Fatalf("unexpected cancellation count: %s, %v", recorder.Body.String(), err)
				}
				if _, exists := body.Data["enabled"]; exists {
					t.Fatal("stop response must not change the schedule enabled state")
				}
			}
		})
	}
}

func TestScheduledJobRunOutputDownload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cves.txt")
	if err := os.WriteFile(path, []byte("CVE-2026-0001\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	stub := &scheduledJobControlStub{output: &dto.ScheduledJobRunOutput{Path: path, FileName: "cves.txt"}}
	h := NewScheduledJobHandler(stub)
	router := gin.New()
	router.GET("/scheduled-job-runs/:run_id/output", h.DownloadRunOutput)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-job-runs/1/output", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "CVE-2026-0001\n" {
		t.Fatalf("status=%d, body=%q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Header().Get("Content-Disposition"), "cves.txt") {
		t.Fatalf("unexpected content disposition: %q", recorder.Header().Get("Content-Disposition"))
	}
}
