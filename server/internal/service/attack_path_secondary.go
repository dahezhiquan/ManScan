package service

import (
	"context"
	"net/netip"
	"net/url"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	"github.com/projectdiscovery/goja/ast"
	"github.com/projectdiscovery/goja/parser"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"mvdan.cc/sh/v3/syntax"
)

// Only corroborate a CRS finding in the same single-valued argument. Negative
// parser results never establish safety; parsing is not execution or validation
// of a real target's behavior. No values are retained in diagnostic evidence.
func corroborateAttackPath(ctx context.Context, u *url.URL, matches []types.MatchedRule) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", nil
	}
	checked := make(map[struct {
		family int
		key    string
	}]bool)
	for _, match := range matches {
		id := match.Rule().ID()
		family := id / 1000
		if family != 931 && family != 932 && family != 934 && family != 941 {
			continue
		}
		detection := false
		for _, tag := range match.Rule().Tags() {
			if strings.HasPrefix(tag, "attack-") {
				detection = true
				break
			}
		}
		if !detection {
			continue
		}
		for _, data := range match.MatchedDatas() {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if data.Variable() != variables.Args && data.Variable() != variables.ArgsGet {
				continue
			}
			items := values[data.Key()]
			if len(items) != 1 || items[0] == "" || len(items[0]) > 2048 {
				continue
			}
			key := struct {
				family int
				key    string
			}{family, data.Key()}
			if checked[key] {
				continue
			}
			checked[key] = true
			value := items[0]
			switch {
			case id >= 932000 && id < 933000:
				if attackPathEnum(data.Key(), "host", "hostname", "ip", "target", "cmd", "command", "exec") && attackPathShellStructure(value) {
					return "crs_shell_structure", nil
				}
			case id >= 941000 && id < 942000:
				if attackPathHTMLStructure(value) {
					return "crs_active_html", nil
				}
			case id >= 931000 && id < 932000 || id >= 934000 && id < 935000:
				if attackPathEnum(data.Key(), "url", "uri", "endpoint", "target") && attackPathMetadataURL(value) {
					return "crs_metadata_url", nil
				}
			}
		}
	}
	return "", ctx.Err()
}

func attackPathShellStructure(value string) bool {
	// Skip plain words and numbers before allocating a parser. Do not decode
	// again: URL parsing already decoded the query once, like the input value.
	if len(value) > 2048 || !strings.ContainsAny(value, ";|&$`\n") {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(value), "")
	if err != nil {
		return false
	}
	substitution := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if substitution {
			return false
		}
		if command, ok := node.(*syntax.CmdSubst); ok && len(command.Stmts) > 0 {
			substitution = true
		}
		return true
	})
	if substitution {
		return true
	}
	// A literal IP followed by a shell statement/operator provides more
	// evidence than two ordinary words, which may simply be prose or a label.
	first := (*syntax.Stmt)(nil)
	if len(file.Stmts) >= 2 {
		first = file.Stmts[0]
	} else if len(file.Stmts) == 1 {
		if binary, ok := file.Stmts[0].Cmd.(*syntax.BinaryCmd); ok {
			first = binary.X
		}
	}
	if first == nil {
		return false
	}
	call, ok := first.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 1 || len(call.Assigns) != 0 {
		return false
	}
	_, err = netip.ParseAddr(call.Args[0].Lit())
	return err == nil
}

func attackPathHTMLStructure(value string) bool {
	if len(value) > 2048 {
		return false
	}
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "<") || !strings.HasSuffix(trimmed, ">") {
		return false
	}
	nodes, err := html.ParseFragment(strings.NewReader(trimmed), &html.Node{Type: html.ElementNode, DataAtom: atom.Div, Data: "div"})
	if err != nil || len(nodes) != 1 || nodes[0].Type != html.ElementNode {
		return false
	}
	root := nodes[0]
	if root.Data == "script" && root.FirstChild != nil && root.FirstChild.Type == html.TextNode {
		for _, attr := range root.Attr {
			if attr.Key == "type" && !attackPathEnum(strings.ToLower(attr.Val), "", "module", "text/javascript", "application/javascript") {
				return false
			}
		}
		return attackPathJavaScript(root.FirstChild.Data)
	}
	// Do not search prose or documentation descendants for embedded examples.
	for _, attr := range root.Attr {
		if attackPathEnum(attr.Key, "onload", "onerror", "onclick", "onfocus", "onmouseover", "onanimationstart") && attackPathJavaScript(attr.Val) {
			return true
		}
		if attr.Key == "href" || attr.Key == "src" || attr.Key == "action" || attr.Key == "formaction" {
			u, err := url.Parse(strings.TrimSpace(attr.Val))
			if err == nil && strings.EqualFold(u.Scheme, "javascript") && attackPathJavaScript(u.Opaque) {
				return true
			}
		}
	}
	return false
}

func attackPathJavaScript(value string) bool {
	// Parse only; never instantiate a JS runtime or evaluate the program. Require
	// a complete executable expression rather than arbitrary nonempty markup.
	program, err := parser.ParseFile(nil, "", value, 0)
	if err != nil || len(program.Body) != 1 {
		return false
	}
	statement, ok := program.Body[0].(*ast.ExpressionStatement)
	if !ok {
		return false
	}
	switch statement.Expression.(type) {
	case *ast.CallExpression, *ast.AssignExpression, *ast.NewExpression:
		return true
	default:
		return false
	}
}

func attackPathMetadataURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	address, err := netip.ParseAddr(u.Hostname())
	if err != nil || address.String() != "169.254.169.254" {
		return false
	}
	// A private/loopback destination alone is not proof of an attack. Limit
	// corroboration to well-known metadata resource paths plus a CRS RFI hit.
	return strings.HasPrefix(u.Path, "/latest/meta-data/") || u.Path == "/latest/meta-data" || strings.HasPrefix(u.Path, "/metadata/instance/") || u.Path == "/metadata/instance"
}
