package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAttackPathRules(t *testing.T) {
	rules, err := newAttackPathRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		path string
		want attackPathDecision
	}{
		{"/api/v1/users/123?page=2", attackPathNormal},
		{"/api/users?request_id=4ade36cb29840f2bacd002fa&page=2", attackPathNormal},
		{"/api/exec?cmd=123", attackPathNormal},
		{"/api/search?q=123", attackPathNormal},
		{"/api?url=2130706433", attackPathNormal},
		{"/orders?page=2&active=true&date=2026-11-17", attackPathNormal},
		{"/api/search?q=1+OR+TRUE", attackPathNormal},
		{"/api/search?q=UNION+SELECT+教程", attackPathUncertain},
		{"/api/search?q=O%27Reilly+books", attackPathNormal},
		{"/api/search?q=测试", attackPathNormal},
		{"/api/orders?status=paid", attackPathNormal},
		{"/orders?status=paid&currency=CNY&locale=zh-CN", attackPathNormal},
		{"/items?cursor=123&width=320&height=240&format=png", attackPathNormal},
		{"/settings?theme=dark&platform=web&environment=staging", attackPathNormal},
		{"/orders?state=open&direction=incoming&order=asc", attackPathNormal},
		{"/settings?language=zh-Hant-TW", attackPathNormal},
		{"/orders?status=paid&unknown=123", attackPathNormal},
		{"/orders?status=paid&status=unpaid", attackPathNormal},
		{"/orders?status=paid&q=free+text", attackPathNormal},
		{"/orders?status=arbitrary", attackPathNormal},
		{"/settings?currency=ZZZ", attackPathNormal},
		{"/settings?currency=XXX", attackPathNormal},
		{"/settings?locale=zh-CN-x-private", attackPathNormal},
		{"/settings?locale=und", attackPathNormal},
		{"/settings?theme=dark%2500", attackPathUncertain},
		{"/settings?role=admin&action=delete", attackPathNormal},
		{"/api/orders?cursor=opaque-token", attackPathNormal},
		{"/api/orders?state=100032", attackPathNormal},
		{"/api/files?path=reports/2026/summary.csv", attackPathNormal},
		{"/api/search?q=x&q=y", attackPathNormal},
		{"/api/users?path=%252525252e", attackPathUncertain},
		{"/api/users?invalid=%zz", attackPathUncertain},
		{"https://user:secret@example.test/api/users", attackPathUncertain},
		{"/api/a#fragment", attackPathUncertain},
		{"/api/a?x=%00", attackPathUncertain},
		{"/api/items?category=books", attackPathNormal},
		{"/api/%75sers", attackPathNormal},
		{"/api/items?unknown=", attackPathNormal},
		{"/api/%zz", attackPathUncertain},
		{"//example.test/api/users", attackPathUncertain},
		{"ftp://example.test/api/users", attackPathUncertain},
		{"/api/items?unknown=ok&bad=%zz", attackPathUncertain},
		// Explicitly record the policy tradeoff: a CRS zero-hit command-like
		// value is now kept, not silently promoted into model review.
		{"/api?host=127.0.0.1%3Bid", attackPathNormal},
	} {
		t.Run(tt.path, func(t *testing.T) {
			r, err := rules.inspect(context.Background(), tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if r.decision != tt.want {
				t.Fatalf("result=%+v want=%d", r, tt.want)
			}
			if r.decision == attackPathNormal && (r.reason != "crs_clean_input" || r.detectionScore != 0 || len(r.ruleIDs) != 0) {
				t.Fatalf("local keep bypassed clean CRS evidence: %+v", r)
			}
			if r.decision == attackPathUncertain && r.reason != "invalid_input" && (r.reason != "crs_review" || r.detectionScore == 0 && len(r.ruleIDs) == 0) {
				t.Fatalf("model review without suspicious evidence: %+v", r)
			}
		})
	}
	// Recognized attacks must not be locally kept; weak CRS evidence still goes to AI.
	for _, path := range []string{
		"/orders?status=paid&q=%27+UNION+SELECT+password+FROM+users--",
		"/settings?format=json&path=..%2Fetc%2Fpasswd",
		"/orders?status=%3Csvg+onload%3Dalert(1)%3E",
		"/settings?locale=en%0d%0aLocation%3Aevil",
		"/api/search?q=%27+UNION+SELECT+password+FROM+users--",
		"/api/items?filter=1+OR+1%3D1--",
		"/api/files?path=..%2Fetc%2Fpasswd",
		"/api/files?path=%252e%252e%252fetc%252fpasswd",
		"/api/files?path=..%5C..%5CWindows%5Cwin.ini",
		"/api?q=%3Csvg+onload%3Dalert(1)%3E",
		"/api?host=%24%28id%29",
		"/api?next=%2Fhome%0d%0aLocation%3Aevil",
		"/api?template=%7B%7B7*7%7D%7D",
		"/api?filter=%7B%22%24where%22%3A%22return+true%22%7D",
		"/api?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data",
		"/api/files?path=../../../etc/passwd&bad=%zz",
		"/.git/config", "/.env.production", "/backup/database.sql",
	} {
		t.Run(path, func(t *testing.T) {
			r, err := rules.inspect(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if r.decision == attackPathNormal {
				t.Fatalf("attack locally kept: %+v", r)
			}
			t.Logf("decision=%d scores=%d/%d rules=%v", r.decision, r.blockingScore, r.detectionScore, r.ruleIDs)
		})
	}
}

func TestAttackPathRulesConcurrentAndCancellation(t *testing.T) {
	rules, err := newAttackPathRules()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				r, err := rules.inspect(context.Background(), "/api/users?page=2")
				if err != nil || r.decision != attackPathNormal {
					t.Errorf("result=%+v err=%v", r, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rules.classify(ctx, "/api/users"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ignored cancellation: %v", err)
	}
}

func TestAttackPathRulesOfflineAndEvidence(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	rules, err := newAttackPathRules()
	if err != nil {
		t.Fatal(err)
	}
	result, err := rules.inspect(context.Background(), server.URL+"/get?arg=../../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	// Adapted from CRS 4.25.0 FTW 930110 test 2; verifies real CRS evidence.
	matched := false
	for _, id := range result.ruleIDs {
		if id == 930110 {
			matched = true
		}
	}
	if requests.Load() != 0 || !matched || result.blockingScore < 10 || result.decision != attackPathMalicious {
		t.Fatalf("requests=%d result=%+v", requests.Load(), result)
	}
	clean, err := rules.inspect(context.Background(), server.URL+"/api/users?page=2")
	if err != nil || clean.blockingScore != 0 || clean.detectionScore != 0 || len(clean.ruleIDs) != 0 || requests.Load() != 0 {
		t.Fatalf("synthetic headers polluted scoring: result=%+v err=%v", clean, err)
	}
}
