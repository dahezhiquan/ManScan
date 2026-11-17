package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestAttackPathSecondaryParsers(t *testing.T) {
	for _, group := range []struct {
		name    string
		check   func(string) bool
		yes, no []string
	}{
		{"shell", attackPathShellStructure,
			[]string{"$(id)", "127.0.0.1; id", "127.0.0.1|whoami", "127.0.0.1 && id", "`id`"},
			[]string{"127.0.0.1", "hello world", "echo '$(id)'", "echo \"\\$(id)\"", "'$(id)'", "hello; world", "$(id", strings.Repeat("x", 2049)}},
		{"html", attackPathHTMLStructure,
			[]string{"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload='alert(1)'></svg>", "<a href='javascript:alert(1)'>go</a>"},
			[]string{"<b>hello</b>", "explain <script>alert(1)</script>", "<pre><script>alert(1)</script></pre>", "<script type='application/json'>{\"a\":1}</script>", "<script type='text/plain'>alert(1)</script>", "<script>// comment</script>", "<script>\"hello\"</script>", "<img onerror='invalid('>", "<img onerror='just_text'>", "&lt;script&gt;alert(1)&lt;/script&gt;", strings.Repeat("x", 2049)}},
		{"metadata", attackPathMetadataURL,
			[]string{"http://169.254.169.254/latest/meta-data/iam/", "http://169.254.169.254/metadata/instance?api-version=1"},
			[]string{"http://127.0.0.1/admin", "http://10.0.0.1/api", "https://example.test/latest/meta-data/", "http://169.254.169.254/", "http://169.254.169.254/latest/meta-data-guide", "http://user@169.254.169.254/latest/meta-data/", "http://169.254.169.254/%6catest/meta-data/", "http://2852039166/latest/meta-data/"}},
	} {
		t.Run(group.name, func(t *testing.T) {
			for _, input := range group.yes {
				if !group.check(input) {
					t.Errorf("missing structural evidence for %q", input)
				}
			}
			for _, input := range group.no {
				if group.check(input) {
					t.Errorf("unexpected structural evidence for %q", input)
				}
			}
		})
	}
}

func TestAttackPathSecondaryRequiresSameArgumentAndFamily(t *testing.T) {
	for _, tt := range []struct {
		name, key, query, want string
		id                     int
	}{
		{"shell", "host", "host=%24%28id%29", "crs_shell_structure", 932999},
		{"different_argument", "marker", "host=%24%28id%29&marker=trigger", "", 932999},
		{"different_family", "host", "host=%24%28id%29", "", 941999},
		{"text_context", "q", "q=%24%28id%29", "", 932999},
		{"duplicate", "host", "host=%24%28id%29&host=127.0.0.1", "", 932999},
		{"double_encoded", "host", "host=%2524%2528id%2529", "", 932999},
		{"invalid_query", "host", "host=%24%28id%29&broken=%zz", "", 932999},
		{"html", "html", "html=" + url.QueryEscape("<img onerror='alert(1)'>"), "crs_active_html", 941999},
		{"html_different_argument", "marker", "html=" + url.QueryEscape("<img onerror='alert(1)'>") + "&marker=trigger", "", 941999},
		{"metadata", "url", "url=" + url.QueryEscape("http://169.254.169.254/latest/meta-data/"), "crs_metadata_url", 931999},
		{"private_url", "url", "url=" + url.QueryEscape("http://10.0.0.1/admin"), "", 931999},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Real Coraza match data verifies collection/key attribution without
			// depending on a particular upstream signature's threshold.
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(fmt.Sprintf("SecRuleEngine DetectionOnly\nSecRule ARGS:%s \"@rx .\" \"id:%d,phase:1,pass,nolog,tag:attack-test\"", tt.key, tt.id)))
			if err != nil {
				t.Fatal(err)
			}
			tx := waf.NewTransaction()
			defer func() {
				if err := tx.Close(); err != nil {
					t.Error(err)
				}
			}()
			raw := "/?" + tt.query
			tx.ProcessURI(raw, "GET", "HTTP/1.1")
			tx.ProcessRequestHeaders()
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			reason, err := corroborateAttackPath(context.Background(), u, tx.MatchedRules())
			if err != nil || reason != tt.want {
				t.Fatalf("reason=%s want=%s err=%v", reason, tt.want, err)
			}
			none, err := corroborateAttackPath(context.Background(), u, nil)
			if err != nil || none != "" {
				t.Fatal("parser result bypassed required CRS evidence")
			}
		})
	}
}

func TestAttackPathSecondaryRealCRS(t *testing.T) {
	rules, err := newAttackPathRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		raw    string
		want   attackPathDecision
		reason string
	}{
		{"/api?host=%24%28id%29", attackPathMalicious, "crs_shell_structure"},
		// SQL-only evidence must not corroborate a Shell syntax finding.
		{"/api?host=%60id%60", attackPathUncertain, "crs_review"},
		// An unrecognized command chain still needs review, never local keep.
		{"/api?host=127.0.0.1%3Bid", attackPathUncertain, "ambiguous_input"},
	} {
		r, err := rules.inspect(context.Background(), tt.raw)
		if err != nil || r.decision != tt.want || r.reason != tt.reason {
			t.Fatalf("missing cross-parser confirmation: result=%+v err=%v", r, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rules.inspect(ctx, "/api?host=%24%28id%29"); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
}
