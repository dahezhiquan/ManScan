package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
}

func (s *scheduledJobControlStub) Pause(context.Context, int64) (*dto.ScheduledJobListItem, error) {
	s.called = true
	return &dto.ScheduledJobListItem{ID: 1}, s.err
}

func (s *scheduledJobControlStub) Resume(context.Context, int64) (*dto.ScheduledJobListItem, error) {
	s.called = true
	return &dto.ScheduledJobListItem{ID: 1, Enabled: true}, s.err
}

func (s *scheduledJobControlStub) Stop(context.Context, int64) (int, error) {
	s.called = true
	return 2, s.err
}

func TestScheduledJobControlHandlers(t *testing.T) {
	for _, action := range []string{"pause", "resume", "stop"} {
		for _, tc := range []struct {
			name   string
			role   string
			id     string
			err    error
			status int
			called bool
		}{
			{name: "admin", role: "admin", id: "1", status: http.StatusOK, called: true},
			{name: "non-admin", role: "user", id: "1", status: http.StatusForbidden},
			{name: "invalid-id", role: "admin", id: "0", status: http.StatusBadRequest},
			{name: "missing", role: "admin", id: "1", err: gorm.ErrRecordNotFound, status: http.StatusNotFound, called: true},
			{name: "database-error", role: "admin", id: "1", err: errors.New("secret SQL error"), status: http.StatusInternalServerError, called: true},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				stub := &scheduledJobControlStub{err: tc.err}
				h := NewScheduledJobHandler(stub)
				router := gin.New()
				router.Use(func(c *gin.Context) { c.Set(middleware.ContextUserRoleKey, tc.role) })
				methods := map[string]gin.HandlerFunc{"pause": h.Pause, "resume": h.Resume, "stop": h.Stop}
				router.POST("/scheduled-jobs/:id/"+action, methods[action])
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/scheduled-jobs/"+tc.id+"/"+action, nil))
				status := tc.status
				if action == "stop" && status == http.StatusOK {
					status = http.StatusAccepted
				}
				if recorder.Code != status || stub.called != tc.called || strings.Contains(recorder.Body.String(), "secret SQL") {
					t.Fatalf("status=%d, called=%v, body=%s", recorder.Code, stub.called, recorder.Body.String())
				}
				if action == "stop" && status == http.StatusAccepted && !strings.Contains(recorder.Body.String(), `"cancel_requested_runs":2`) {
					t.Fatalf("missing cancellation count: %s", recorder.Body.String())
				}
			})
		}
	}
}
