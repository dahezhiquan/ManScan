package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

type attackPathDecision uint8

const (
	attackPathUncertain attackPathDecision = iota
	attackPathNormal
	attackPathMalicious
)

// CRS provides primary attack signatures. Bounded secondary parsers can
// corroborate its argument-level evidence; no parser runs a payload.
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
	result.reason = "invalid_input"
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if raw == "" || len(raw) > 2048 || !utf8.ValidString(raw) {
		return result, nil
	}
	u, parseErr := url.Parse(raw)
	if parseErr != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https") || (u.Scheme != "" && u.Host == "") || (u.Scheme == "" && (u.Host != "" || !strings.HasPrefix(raw, "/"))) {
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
		reason, err := corroborateAttackPath(ctx, u, tx.MatchedRules())
		if err != nil {
			return result, err
		}
		if reason != "" {
			result.decision = attackPathMalicious
			result.reason = reason
			return result, nil
		}
		result.reason = "crs_review"
		return result, nil
	}
	// Invalid query encoding is suspicious input, not an unknown business type.
	// Do not let a partial parser result become a clean classification.
	if _, queryErr := url.ParseQuery(u.RawQuery); queryErr != nil {
		return result, nil
	}
	// A successfully scanned path with no CRS evidence is kept locally, even
	// when its query parameter types are unknown. Only suspicious evidence or
	// input that cannot be reliably scanned requires model review. This policy
	// intentionally accepts attacks that the loaded rules do not recognize.
	result.decision = attackPathNormal
	result.reason = "crs_clean_input"
	return result, nil
}

// attackPathEnum limits the parameter names and structures used by secondary parsers.
func attackPathEnum(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
