package service

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Explicitly opt in. Diagnostics contain counts and rule IDs, never raw paths or values.
func TestAttackPathRulesProfile(t *testing.T) {
	path := os.Getenv("MANSCAN_TEST_ATTACK_PATH_INPUT")
	if path == "" {
		t.Skip("set MANSCAN_TEST_ATTACK_PATH_INPUT to profile local review reasons")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("cannot open profile input")
	}
	defer f.Close()
	rules, err := newAttackPathRules()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		raw := scanner.Text()
		r, err := rules.inspect(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		counts["reason/"+r.reason]++
		for _, id := range r.ruleIDs {
			counts["rule/"+strconv.Itoa(id)]++
		}
		if r.reason != "ambiguous_input" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			continue
		}
		for key, values := range values {
			for _, value := range values {
				if attackPathScalar(key, value) {
					continue
				}
				// Only print common public parameter labels, never arbitrary input keys.
				label := "other"
				switch key {
				case "status", "state", "sort", "order", "lang", "locale", "q", "query", "keyword", "search", "category", "type", "format", "path", "file", "url", "redirect", "next", "cmd", "filter":
					label = key
				}
				shape := "complex"
				if value != "" && len(value) <= 32 && strings.IndexFunc(value, func(c rune) bool {
					return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-')
				}) == -1 {
					shape = "short_token"
				}
				counts["untyped/"+label+"/"+shape]++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal("cannot read profile input")
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		t.Logf("%s=%d", key, counts[key])
	}
}
