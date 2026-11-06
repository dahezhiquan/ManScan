package middleware

import (
	"net/http"
	"testing"
	"time"
)

func TestShouldLogHTTPRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		method  string
		route   string
		status  int
		latency time.Duration
		want    bool
	}{
		{name: "scan list poll", method: http.MethodGet, route: "/api/v1/scans", status: http.StatusOK},
		{name: "scan stats poll", method: http.MethodGet, route: "/api/v1/scans/stats", status: http.StatusOK},
		{name: "scan detail poll", method: http.MethodGet, route: "/api/v1/scans/:id", status: http.StatusOK},
		{name: "slow poll", method: http.MethodGet, route: "/api/v1/scans/:id", status: http.StatusOK, latency: time.Second, want: true},
		{name: "unauthorized poll", method: http.MethodGet, route: "/api/v1/scans", status: http.StatusUnauthorized, want: true},
		{name: "failed poll", method: http.MethodGet, route: "/api/v1/scans/stats", status: http.StatusInternalServerError, want: true},
		{name: "other scan read", method: http.MethodGet, route: "/api/v1/scans/:id/logs", status: http.StatusOK, want: true},
		{name: "scan write", method: http.MethodPost, route: "/api/v1/scans", status: http.StatusOK, want: true},
		{name: "unknown route", method: http.MethodGet, route: "", status: http.StatusNotFound, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldLogHTTPRequest(tt.method, tt.route, tt.status, tt.latency); got != tt.want {
				t.Fatalf("shouldLogHTTPRequest(%q, %q, %d, %s) = %t, want %t", tt.method, tt.route, tt.status, tt.latency, got, tt.want)
			}
		})
	}
}
