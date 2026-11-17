package service

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"golang.org/x/text/currency"
	"golang.org/x/text/language"
)

type attackPathDecision uint8

const (
	attackPathUncertain attackPathDecision = iota
	attackPathNormal
	attackPathMalicious
)

// Attack signatures and transformations come exclusively from the pinned CRS.
// The local policy only decides whether that evidence is sufficient without AI.
const attackPathCRSDirectives = `
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off
SecDebugLogLevel 0
Include @crs-setup.conf.example
SecAction "id:1000001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=2,setvar:tx.inbound_anomaly_score_threshold=10"
Include @owasp_crs/REQUEST-901-INITIALIZATION.conf
Include @owasp_crs/REQUEST-905-COMMON-EXCEPTIONS.conf
Include @owasp_crs/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include @owasp_crs/REQUEST-921-PROTOCOL-ATTACK.conf
Include @owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include @owasp_crs/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include @owasp_crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include @owasp_crs/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include @owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include @owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include @owasp_crs/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include @owasp_crs/REQUEST-944-APPLICATION-ATTACK-JAVA.conf
Include @owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf
`

type attackPathLocalClassifier interface {
	classify(ctx context.Context, raw string) (attackPathDecision, error)
}

type attackPathRules struct{ waf coraza.WAF }

type attackPathRuleResult struct {
	decision                      attackPathDecision
	blockingScore, detectionScore int
	ruleIDs                       []int
	reason                        string
}

func newAttackPathRules() (*attackPathRules, error) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).
		WithDirectives(attackPathCRSDirectives).
		WithErrorCallback(func(types.MatchedRule) {}))
	if err != nil {
		return nil, fmt.Errorf("初始化离线 CRS 规则失败: %w", err)
	}
	return &attackPathRules{waf: waf}, nil
}

func (r *attackPathRules) classify(ctx context.Context, raw string) (attackPathDecision, error) {
	result, err := r.inspect(ctx, raw)
	return result.decision, err
}

func (r *attackPathRules) inspect(ctx context.Context, raw string) (result attackPathRuleResult, err error) {
	result.reason = "ambiguous_input"
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if raw == "" || len(raw) > 2048 || !utf8.ValidString(raw) {
		return result, nil
	}
	u, parseErr := url.Parse(raw)
	if parseErr != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https") || (u.Scheme != "" && u.Host == "") || (u.Scheme == "" && !strings.HasPrefix(raw, "/")) {
		return result, nil
	}
	// Preserve the raw path and query for Coraza; do not decode, clean or deduplicate.
	uri := u.RequestURI()
	tx := r.waf.NewTransaction()
	defer func() {
		if closeErr := tx.Close(); err == nil && closeErr != nil {
			err = errors.New("关闭离线 CRS 事务失败")
		}
	}()
	// These fixed fields are adapter context, not observations about a real request.
	// No network, body, response, scanner-UA or method-enforcement phase is used.
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "offline.invalid")
	tx.SetServerName("offline.invalid")
	tx.AddRequestHeader("User-Agent", "ManScanOfflineClassifier")
	tx.AddRequestHeader("Accept", "*/*")
	tx.ProcessRequestHeaders()
	if _, bodyErr := tx.ProcessRequestBody(); bodyErr != nil {
		return result, errors.New("离线 CRS 判定失败")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// The plugin interface is pinned together with the engine. Fail rather than
	// interpreting a missing/unparseable CRS score as zero.
	state, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return result, errors.New("离线 CRS 评分接口不可用")
	}
	score := func(key string) (int, error) {
		values := state.Variables().TX().Get(key)
		if len(values) != 1 {
			return 0, errors.New("离线 CRS 评分缺失")
		}
		n, e := strconv.Atoi(values[0])
		if e != nil || n < 0 {
			return 0, errors.New("离线 CRS 评分无效")
		}
		return n, nil
	}
	if result.blockingScore, err = score("blocking_inbound_anomaly_score"); err != nil {
		return result, err
	}
	if result.detectionScore, err = score("detection_inbound_anomaly_score"); err != nil {
		return result, err
	}
	seen := map[int]bool{}
	attackHits := 0
	for _, match := range tx.MatchedRules() {
		id := match.Rule().ID()
		isDetection := false
		for _, tag := range match.Rule().Tags() {
			if strings.HasPrefix(tag, "attack-") {
				isDetection = true
				break
			}
		}
		if id < 920000 || id >= 949000 || seen[id] || !isDetection {
			continue
		}
		seen[id] = true
		result.ruleIDs = append(result.ruleIDs, id)
		if id >= 930000 {
			attackHits++
		}
	}
	// A single broad signature (including a legitimate search for SQL syntax)
	// is reviewed instead of being discarded. PL2-only hits also go to AI.
	if result.blockingScore >= 10 && attackHits >= 2 {
		result.decision = attackPathMalicious
		result.reason = "crs_high_score"
		return result, nil
	}
	if result.detectionScore > 0 || len(result.ruleIDs) > 0 {
		result.reason = "crs_review"
		return result, nil
	}
	if !unambiguousAttackPathInput(u) {
		return result, nil
	}
	result.decision = attackPathNormal
	result.reason = "crs_clean_scalar_input"
	return result, nil
}

// This is a representation/typing policy, not an attack-signature allowlist.
// A clean CRS result is necessary. Free text, unknown value types, duplicate
// arguments and encoded paths still require AI, regardless of an /api prefix.
func unambiguousAttackPathInput(u *url.URL) bool {
	if u.Host != "" && u.Scheme == "" {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	for _, c := range path {
		if !asciiPathCharacter(c) {
			return false
		}
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for key, items := range values {
		if key == "" || len(key) > 64 || len(items) != 1 {
			return false
		}
		for _, c := range key {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (c >= '0' && c <= '9')) {
				return false
			}
		}
		if !attackPathScalar(key, items[0]) {
			return false
		}
	}
	return true
}

func asciiPathCharacter(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '-' || c == '_' || c == '.'
}

func attackPathScalar(key, s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	switch key {
	case "active", "enabled", "include_deleted":
		return s == "true" || s == "false"
	case "date", "from", "to", "start_date", "end_date":
		_, err := time.Parse("2006-01-02", s)
		return err == nil
	case "currency":
		unit, err := currency.ParseISO(s)
		return err == nil && unit.String() == s && s != "XXX" && s != "XTS"
	case "language", "locale", "lang":
		return attackPathLanguageTag(s)
	case "format":
		return attackPathEnum(s, "json", "xml", "csv", "tsv", "txt", "pdf", "png", "jpg", "jpeg", "gif", "webp")
	case "theme":
		return attackPathEnum(s, "light", "dark", "auto", "system")
	case "platform":
		return attackPathEnum(s, "web", "ios", "android", "windows", "macos", "linux")
	case "environment":
		return attackPathEnum(s, "production", "staging", "development", "test", "testing", "local")
	case "direction", "order":
		return attackPathEnum(s, "asc", "desc", "ascending", "descending", "incoming", "outgoing", "forward", "backward")
	case "status", "state":
		return attackPathEnum(s, "pending", "active", "inactive", "enabled", "disabled", "open", "closed", "paid", "unpaid", "processing", "completed", "failed", "canceled", "cancelled", "shipped", "delivered", "draft", "published", "archived")
	}
	isID := key == "id" || strings.HasSuffix(key, "_id")
	if !isID {
		switch key {
		case "page", "page_size", "per_page", "limit", "offset", "size", "cursor", "width", "height":
		default:
			return false
		}
	}
	numeric := true
	for _, c := range s {
		if c < '0' || c > '9' {
			numeric = false
			break
		}
	}
	if numeric {
		return true
	}
	if !isID {
		return false
	}
	if len(s) == 24 || len(s) == 32 || len(s) == 64 {
		_, err := hex.DecodeString(s)
		return err == nil
	}
	if len(s) == 36 {
		for i, c := range s {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				if c != '-' {
					return false
				}
				continue
			}
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}
	return false
}

// These exact value sets are a conservative input representation policy, not
// route authorization or an attack allowlist. Unknown values still go to AI.
func attackPathEnum(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func attackPathLanguageTag(value string) bool {
	tag, err := language.Parse(value)
	if err != nil || tag.String() != value || len(tag.Extensions()) != 0 || len(tag.Variants()) != 0 {
		return false
	}
	base, _, _ := tag.Raw()
	return base.String() != "und"
}
