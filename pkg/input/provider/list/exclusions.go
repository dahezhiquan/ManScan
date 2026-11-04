package list

import (
	"net"
	"regexp"
	"strings"

	"github.com/projectdiscovery/mapcidr/asn"
	iputil "github.com/projectdiscovery/utils/ip"
	urlutil "github.com/projectdiscovery/utils/url"
)

// ExcludedTarget records the rule that prevents a target from being scanned.
type ExcludedTarget struct {
	Target string
	Rule   string
}

type exclusionRule struct {
	raw      string
	hostname string
	port     string
	regex    *regexp.Regexp
	network  *net.IPNet
}

// ExclusionMatcher applies the input provider's target exclusion semantics.
type ExclusionMatcher struct {
	rules []exclusionRule
}

// NewExclusionMatcher prepares host, port, regex, CIDR, and ASN exclusions.
func NewExclusionMatcher(values []string) *ExclusionMatcher {
	matcher := &ExclusionMatcher{rules: make([]exclusionRule, 0, len(values))}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if iputil.IsCIDR(value) {
			if _, network, err := net.ParseCIDR(value); err == nil {
				matcher.rules = append(matcher.rules, exclusionRule{raw: value, network: network})
			}
			continue
		}
		if asn.IsASN(value) {
			if networks, err := asn.GetCIDRsForASNNum(value); err == nil {
				for _, network := range networks {
					matcher.rules = append(matcher.rules, exclusionRule{raw: value, network: network})
				}
			}
			continue
		}
		if rule, ok := parseHostExclusion(value); ok {
			matcher.rules = append(matcher.rules, rule)
		}
	}
	return matcher
}

// Match returns the first exclusion rule matching a target.
func (m *ExclusionMatcher) Match(target string) (string, bool) {
	if m == nil {
		return "", false
	}
	parsed, err := urlutil.ParseURL(target, true)
	if err != nil {
		return "", false
	}
	for _, rule := range m.rules {
		if rule.matches(parsed.Hostname(), parsed.Port(), parsed.Host, "") {
			return rule.raw, true
		}
	}
	return "", false
}

// Filter separates preflight targets from targets blocked by exclusion rules.
func (m *ExclusionMatcher) Filter(targets []string) ([]string, []ExcludedTarget) {
	allowed := make([]string, 0, len(targets))
	excluded := make([]ExcludedTarget, 0)
	for _, target := range targets {
		if rule, matched := m.Match(target); matched {
			excluded = append(excluded, ExcludedTarget{Target: target, Rule: rule})
		} else {
			allowed = append(allowed, target)
		}
	}
	return allowed, excluded
}

func parseHostExclusion(value string) (exclusionRule, bool) {
	parsed, err := urlutil.ParseURL(value, true)
	if err != nil {
		return exclusionRule{}, false
	}
	rule := exclusionRule{raw: value, hostname: parsed.Hostname(), port: parsed.Port()}
	if net.ParseIP(rule.hostname) == nil && !strings.Contains(value, "://") && strings.ContainsAny(value, `*+?[](){}|^$\`) {
		rule.regex, _ = regexp.Compile(value)
	}
	return rule, true
}

func (r exclusionRule) matches(hostname, port, hostWithPort, customIP string) bool {
	if r.network != nil {
		return r.network.Contains(net.ParseIP(hostname)) || (customIP != "" && r.network.Contains(net.ParseIP(customIP)))
	}
	matchingHost := strings.EqualFold(hostname, r.hostname)
	if ip := net.ParseIP(r.hostname); ip != nil {
		matchingHost = ip.Equal(net.ParseIP(hostname))
	}
	return (matchingHost && (r.port == "" || r.port == port)) || (r.regex != nil && r.regex.MatchString(hostWithPort))
}
